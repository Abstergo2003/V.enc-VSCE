import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import * as crypto from 'crypto';
import { 
    encrypt, 
    decrypt, 
    encryptSsh, 
    decryptSsh, 
    parseSshRsaToJwk, 
    MAGIC, 
    MAGIC_SSH 
} from './crypto';

// In-memory password store: directoryKey -> password
const passwordMap = new Map<string, string>();
const pendingPasswordPrompts = new Map<string, Promise<string | undefined>>();

let statusBarItem: vscode.StatusBarItem;
let vencFileSystemProvider: VEncFileSystemProvider | undefined;

let cachedPrivateKey: crypto.KeyObject | undefined;

function expandHomeDir(pathStr: string): string {
    if (pathStr.startsWith('~')) {
        return path.join(os.homedir(), pathStr.slice(1));
    }
    return pathStr;
}

function getPublicKey(publicKeyPath: string): crypto.KeyObject {
    const expandedPath = expandHomeDir(publicKeyPath);
    if (!fs.existsSync(expandedPath)) {
        throw new Error(`SSH public key file not found at: ${expandedPath}`);
    }
    const publicKeyStr = fs.readFileSync(expandedPath, 'utf8').trim();
    if (publicKeyStr.startsWith('-----BEGIN')) {
        return crypto.createPublicKey(publicKeyStr);
    }
    const jwk = parseSshRsaToJwk(publicKeyStr);
    return crypto.createPublicKey({
        key: jwk,
        format: 'jwk'
    });
}

async function getPrivateKey(privateKeyPath: string): Promise<crypto.KeyObject | undefined> {
    if (cachedPrivateKey) {
        return cachedPrivateKey;
    }
    
    const expandedPath = expandHomeDir(privateKeyPath);
    if (!fs.existsSync(expandedPath)) {
        throw new Error(`SSH private key file not found at: ${expandedPath}`);
    }
    
    const privateKeyPem = fs.readFileSync(expandedPath, 'utf8');
    
    // Try to load without passphrase first
    try {
        const key = crypto.createPrivateKey(privateKeyPem);
        cachedPrivateKey = key;
        return key;
    } catch (err: any) {
        // If it requires a passphrase, prompt the user
        const isPassphraseRequired = 
            err.message.includes('passphrase') || 
            err.message.includes('password') || 
            err.message.includes('key val') || 
            err.message.includes('DECODER') ||
            err.message.includes('Unsupported state');
            
        if (isPassphraseRequired) {
            const passphrase = await vscode.window.showInputBox({
                prompt: `Enter passphrase for SSH private key: ${expandedPath}`,
                password: true,
                ignoreFocusOut: true
            });
            if (!passphrase) {
                return undefined;
            }
            try {
                const key = crypto.createPrivateKey({
                    key: privateKeyPem,
                    passphrase: passphrase
                });
                cachedPrivateKey = key;
                return key;
            } catch (innerErr: any) {
                throw new Error(`Invalid passphrase for SSH private key: ${innerErr.message}`);
            }
        } else {
            throw err;
        }
    }
}

function getDirectoryKey(uri: vscode.Uri): string {
    // Look up the workspace folder using the original URI (matching scheme like 'venc' or 'file')
    const workspaceFolder = vscode.workspace.getWorkspaceFolder(uri);
    let key: string;
    if (workspaceFolder) {
        // Normalize the scheme to 'file' and lowercase to handle case-insensitive paths
        key = workspaceFolder.uri.with({ scheme: 'file' }).toString().toLowerCase();
        console.log(`[V.enc] getDirectoryKey(${uri.toString()}): Found workspace folder -> ${key}`);
    } else {
        // Fallback to parent directory of the file (normalized to 'file' scheme and lowercase)
        const fileUri = uri.with({ scheme: 'file' });
        const parentDir = fileUri.with({ path: path.dirname(fileUri.path) });
        key = parentDir.toString().toLowerCase();
        console.log(`[V.enc] getDirectoryKey(${uri.toString()}): No workspace folder, fell back to parent dir -> ${key}`);
    }
    return key;
}

const virtualMtimes = new Map<string, number>();

async function reloadWorkspaceVEncFiles() {
    if (!vencFileSystemProvider) {
        return;
    }
    try {
        const fileUris = await vscode.workspace.findFiles('**/*.venc');
        const changeEvents = fileUris.map(uri => {
            const vencUri = uri.with({ scheme: 'venc' });
            const key = vencUri.toString().toLowerCase();
            virtualMtimes.set(key, Date.now());
            console.log(`[V.enc] reloadWorkspaceVEncFiles: Bumping virtual mtime for key ${key}`);
            return {
                type: vscode.FileChangeType.Changed,
                uri: vencUri
            };
        });
        if (changeEvents.length > 0) {
            vencFileSystemProvider.fireFileChanges(changeEvents);
        }
    } catch (err) {
        console.error('Failed to trigger reload of .venc files:', err);
    }
}

async function getPasswordForUri(uri: vscode.Uri, promptIfMissing: boolean = true): Promise<string | undefined> {
    const key = getDirectoryKey(uri);
    if (passwordMap.has(key)) {
        const password = passwordMap.get(key);
        console.log(`[V.enc] getPasswordForUri(${uri.toString()}): Found cached password for key ${key} -> ${password}`);
        return password;
    }
    if (!promptIfMissing) {
        console.log(`[V.enc] getPasswordForUri(${uri.toString()}): No cached password for key ${key}, promptIfMissing is false`);
        return undefined;
    }
    
    if (pendingPasswordPrompts.has(key)) {
        console.log(`[V.enc] getPasswordForUri(${uri.toString()}): Re-using pending password prompt for key ${key}`);
        return pendingPasswordPrompts.get(key);
    }
    
    console.log(`[V.enc] getPasswordForUri(${uri.toString()}): Prompting user for password for key ${key}`);
    const promptPromise = (async () => {
        const password = await vscode.window.showInputBox({
            prompt: `Enter decryption password for V.enc files in this folder`,
            password: true,
            placeHolder: "Password",
            ignoreFocusOut: true
        });
        
        if (password) {
            console.log(`[V.enc] getPasswordForUri(${uri.toString()}): User entered password -> ${password}`);
            passwordMap.set(key, password);
            updateStatusBar();
            return password;
        }
        console.log(`[V.enc] getPasswordForUri(${uri.toString()}): User cancelled password prompt`);
        return undefined;
    })();
    
    pendingPasswordPrompts.set(key, promptPromise);
    
    try {
        return await promptPromise;
    } finally {
        pendingPasswordPrompts.delete(key);
    }
}

function updateStatusBar() {
    if (!statusBarItem) {
        return;
    }
    let activeUri: vscode.Uri | undefined;
    if (vscode.window.activeTextEditor) {
        activeUri = vscode.window.activeTextEditor.document.uri;
    } else if (vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0) {
        activeUri = vscode.workspace.workspaceFolders[0].uri;
    }
    
    if (!activeUri) {
        statusBarItem.text = `$(lock) V.enc: No Active Dir`;
        statusBarItem.tooltip = "Open a file or folder to set password";
        return;
    }
    
    const key = getDirectoryKey(activeUri);
    const hasPassword = passwordMap.has(key);
    
    if (hasPassword) {
        statusBarItem.text = `$(unlock) V.enc: Active`;
        statusBarItem.tooltip = "Click to change/clear password for this directory";
    } else {
        statusBarItem.text = `$(lock) V.enc: Not Set`;
        statusBarItem.tooltip = "Click to set a password for this directory";
    }
}

export class VEncFileSystemProvider implements vscode.FileSystemProvider {
    private _emitter = new vscode.EventEmitter<vscode.FileChangeEvent[]>();
    readonly onDidChangeFile: vscode.Event<vscode.FileChangeEvent[]> = this._emitter.event;

    fireFileChanges(events: vscode.FileChangeEvent[]) {
        this._emitter.fire(events);
    }

    watch(uri: vscode.Uri, options: { readonly recursive: boolean; readonly excludes: readonly string[] }): vscode.Disposable {
        const fileUri = uri.with({ scheme: 'file' });
        try {
            const globPattern = new vscode.RelativePattern(
                vscode.Uri.file(path.dirname(fileUri.fsPath)),
                options.recursive ? '**/*' : '*'
            );
            const watcher = vscode.workspace.createFileSystemWatcher(globPattern);
            
            const changeSub = watcher.onDidChange(e => {
                this._emitter.fire([{ type: vscode.FileChangeType.Changed, uri: e.with({ scheme: 'venc' }) }]);
            });
            const createSub = watcher.onDidCreate(e => {
                this._emitter.fire([{ type: vscode.FileChangeType.Created, uri: e.with({ scheme: 'venc' }) }]);
            });
            const deleteSub = watcher.onDidDelete(e => {
                this._emitter.fire([{ type: vscode.FileChangeType.Deleted, uri: e.with({ scheme: 'venc' }) }]);
            });
            
            return new vscode.Disposable(() => {
                changeSub.dispose();
                createSub.dispose();
                deleteSub.dispose();
                watcher.dispose();
            });
        } catch (err) {
            console.error('Failed to create file watcher in VEncFS:', err);
            return new vscode.Disposable(() => {});
        }
    }

    async stat(uri: vscode.Uri): Promise<vscode.FileStat> {
        const fileUri = uri.with({ scheme: 'file' });
        const stat = await vscode.workspace.fs.stat(fileUri);
        
        const key = uri.toString().toLowerCase();
        if (virtualMtimes.has(key)) {
            const virtualMtime = virtualMtimes.get(key)!;
            console.log(`[V.enc] stat(${uri.toString()}): Overriding physical mtime ${stat.mtime} with virtual mtime ${virtualMtime}`);
            return {
                ...stat,
                mtime: virtualMtime
            };
        }
        
        return stat;
    }

    async readDirectory(uri: vscode.Uri): Promise<[string, vscode.FileType][]> {
        const fileUri = uri.with({ scheme: 'file' });
        return await vscode.workspace.fs.readDirectory(fileUri);
    }

    async createDirectory(uri: vscode.Uri): Promise<void> {
        const fileUri = uri.with({ scheme: 'file' });
        await vscode.workspace.fs.createDirectory(fileUri);
    }

    async readFile(uri: vscode.Uri): Promise<Uint8Array> {
        const fileUri = uri.with({ scheme: 'file' });
        console.log(`[V.enc] readFile(${uri.toString()}): Reading from fileUri ${fileUri.toString()}`);
        const content = await vscode.workspace.fs.readFile(fileUri);
        
        // Only decrypt if it has the .venc extension
        if (!uri.path.toLowerCase().endsWith('.venc')) {
            console.log(`[V.enc] readFile(${uri.toString()}): File does not end with .venc, passing through raw content of size ${content.length}`);
            return content;
        }
        
        if (content.length === 0) {
            console.log(`[V.enc] readFile(${uri.toString()}): File is empty, passing through 0 bytes`);
            return content;
        }

        // Check magic headers
        const isSsh = content.length >= MAGIC_SSH.length && Buffer.from(content).subarray(0, MAGIC_SSH.length).equals(MAGIC_SSH);
        const isPwd = content.length >= MAGIC.length && Buffer.from(content).subarray(0, MAGIC.length).equals(MAGIC);
        
        console.log(`[V.enc] readFile(${uri.toString()}): Magic check -> isSsh: ${isSsh}, isPwd: ${isPwd}`);
        if (!isSsh && !isPwd) {
            console.log(`[V.enc] readFile(${uri.toString()}): Missing both VENC and VESH magic headers, treating as unencrypted plaintext`);
            return content;
        }

        if (isSsh) {
            const config = vscode.workspace.getConfiguration('v-enc');
            const privateKeyPath = config.get<string>('sshPrivateKeyPath') || '~/.ssh/id_rsa';
            try {
                console.log(`[V.enc] readFile(${uri.toString()}): Loading SSH private key from ${privateKeyPath}`);
                const privateKeyObj = await getPrivateKey(privateKeyPath);
                if (!privateKeyObj) {
                    throw new Error('SSH private key password prompt cancelled or key loading failed.');
                }
                console.log(`[V.enc] readFile(${uri.toString()}): Decrypting with SSH private key`);
                const plaintextStr = decryptSsh(Buffer.from(content), privateKeyObj);
                console.log(`[V.enc] readFile(${uri.toString()}): Decryption succeeded! Length -> ${plaintextStr.length}`);
                return Buffer.from(plaintextStr, 'utf8');
            } catch (err: any) {
                console.error(`[V.enc] readFile(${uri.toString()}): SSH decryption failed: ${err.message}`);
                const choice = await vscode.window.showErrorMessage(
                    `Failed to decrypt secure SSH file ${path.basename(uri.fsPath)}: ${err.message || err}`,
                    'Retry loading private key',
                    'Open as raw ciphertext'
                );
                if (choice === 'Retry loading private key') {
                    cachedPrivateKey = undefined; // clear cache to force passphrase re-entry
                    return this.readFile(uri);
                } else if (choice === 'Open as raw ciphertext') {
                    return content;
                }
                throw new Error('Decryption failed.');
            }
        } else {
            // Password mode
            const password = await getPasswordForUri(uri, true);
            if (!password) {
                console.error(`[V.enc] readFile(${uri.toString()}): Password is missing or user cancelled`);
                throw new Error('Password required to decrypt file.');
            }

            try {
                console.log(`[V.enc] readFile(${uri.toString()}): Decrypting with password -> ${password}`);
                const plaintextStr = decrypt(Buffer.from(content), password);
                console.log(`[V.enc] readFile(${uri.toString()}): Decryption succeeded! Length -> ${plaintextStr.length}`);
                return Buffer.from(plaintextStr, 'utf8');
            } catch (err: any) {
                console.error(`[V.enc] readFile(${uri.toString()}): Password decryption failed: ${err.message}`);
                const choice = await vscode.window.showErrorMessage(
                    `Failed to decrypt ${path.basename(uri.fsPath)}: ${err.message || err}`,
                    'Retry with password',
                    'Open as raw ciphertext'
                );
                if (choice === 'Retry with password') {
                    const key = getDirectoryKey(uri);
                    passwordMap.delete(key);
                    return this.readFile(uri);
                } else if (choice === 'Open as raw ciphertext') {
                    return content;
                }
                throw new Error('Decryption failed.');
            }
        }
    }

    async writeFile(uri: vscode.Uri, content: Uint8Array, options: { create: boolean; overwrite: boolean }): Promise<void> {
        const fileUri = uri.with({ scheme: 'file' });
        console.log(`[V.enc] writeFile(${uri.toString()}): Writing to fileUri ${fileUri.toString()}`);
        
        // Only encrypt if it has the .venc extension
        if (!uri.path.toLowerCase().endsWith('.venc')) {
            console.log(`[V.enc] writeFile(${uri.toString()}): File does not end with .venc, writing unencrypted`);
            await vscode.workspace.fs.writeFile(fileUri, content);
            return;
        }
        
        const config = vscode.workspace.getConfiguration('v-enc');
        const mode = config.get<string>('encryptionMode') || 'password';
        const plaintextStr = Buffer.from(content).toString('utf8');
        let encryptedBuffer: Buffer;
        
        if (mode === 'sshKey') {
            const publicKeyPath = config.get<string>('sshPublicKeyPath') || '~/.ssh/id_rsa.pub';
            try {
                console.log(`[V.enc] writeFile(${uri.toString()}): Encrypting using SSH public key at ${publicKeyPath}`);
                const publicKeyObj = getPublicKey(publicKeyPath);
                encryptedBuffer = encryptSsh(plaintextStr, publicKeyObj);
                console.log(`[V.enc] writeFile(${uri.toString()}): SSH encryption succeeded. Payload size -> ${encryptedBuffer.length}`);
            } catch (err: any) {
                console.error(`[V.enc] writeFile(${uri.toString()}): SSH encryption failed: ${err.message}`);
                vscode.window.showErrorMessage(`Failed to encrypt file with SSH key: ${err.message}`);
                throw err;
            }
        } else {
            // Password mode
            const password = await getPasswordForUri(uri, true);
            if (!password) {
                console.error(`[V.enc] writeFile(${uri.toString()}): Password required but missing`);
                throw new Error('Password is required to save encrypted .venc file.');
            }

            console.log(`[V.enc] writeFile(${uri.toString()}): Encrypting plaintext with password -> ${password}`);
            encryptedBuffer = encrypt(plaintextStr, password);
            console.log(`[V.enc] writeFile(${uri.toString()}): Password encryption succeeded. Payload size -> ${encryptedBuffer.length}`);
        }
        
        // Clear virtual mtime so stat returns the real disk state
        const key = uri.toString().toLowerCase();
        virtualMtimes.delete(key);
        
        await vscode.workspace.fs.writeFile(fileUri, encryptedBuffer);
    }

    async delete(uri: vscode.Uri, options: { recursive: boolean }): Promise<void> {
        const fileUri = uri.with({ scheme: 'file' });
        await vscode.workspace.fs.delete(fileUri, options);
    }

    async rename(oldUri: vscode.Uri, newUri: vscode.Uri, options: { overwrite: boolean }): Promise<void> {
        const oldFileUri = oldUri.with({ scheme: 'file' });
        const newFileUri = newUri.with({ scheme: 'file' });
        await vscode.workspace.fs.rename(oldFileUri, newFileUri, options);
    }
}

let isRedirecting = false;

async function redirectIfNeeded(editor: vscode.TextEditor | undefined) {
    if (isRedirecting || !editor) {
        return;
    }
    
    const uri = editor.document.uri;
    if (uri.scheme === 'file' && uri.path.toLowerCase().endsWith('.venc')) {
        isRedirecting = true;
        try {
            // Close the current file:// editor
            await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
            
            // Open the venc:// editor
            const vencUri = uri.with({ scheme: 'venc' });
            const doc = await vscode.workspace.openTextDocument(vencUri);
            await vscode.window.showTextDocument(doc, {
                preview: false
            });
        } catch (err: any) {
            vscode.window.showErrorMessage(`Failed to open secure editor: ${err.message || err}`);
        } finally {
            isRedirecting = false;
        }
    }
}

async function encryptAndRedirectOnSave(document: vscode.TextDocument) {
    if (isRedirecting) {
        return;
    }
    const uri = document.uri;
    if (uri.scheme === 'file' && uri.path.toLowerCase().endsWith('.venc')) {
        isRedirecting = true;
        try {
            const vencUri = uri.with({ scheme: 'venc' });
            const text = document.getText();
            
            // Write to venc:// which will encrypt and write to file://
            await vscode.workspace.fs.writeFile(vencUri, Buffer.from(text, 'utf8'));
            
            // Close the current file:// editor
            await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
            
            // Open the venc:// editor
            const doc = await vscode.workspace.openTextDocument(vencUri);
            await vscode.window.showTextDocument(doc, {
                preview: false
            });
        } catch (err: any) {
            vscode.window.showErrorMessage(`Failed to secure V.enc file: ${err.message || err}`);
        } finally {
            isRedirecting = false;
        }
    }
}

export function activate(context: vscode.ExtensionContext) {
    console.log('V.enc extension is now active!');

    // Register FileSystemProvider
    vencFileSystemProvider = new VEncFileSystemProvider();
    context.subscriptions.push(
        vscode.workspace.registerFileSystemProvider('venc', vencFileSystemProvider, {
            isCaseSensitive: true,
            isReadonly: false
        })
    );

    // Register Commands
    context.subscriptions.push(
        vscode.commands.registerCommand('v-enc.setPassword', async () => {
            let activeUri: vscode.Uri | undefined;
            if (vscode.window.activeTextEditor) {
                activeUri = vscode.window.activeTextEditor.document.uri;
            } else if (vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0) {
                activeUri = vscode.workspace.workspaceFolders[0].uri;
            }
            
            if (!activeUri) {
                vscode.window.showWarningMessage("No active workspace or file to set password for.");
                return;
            }
            
            const key = getDirectoryKey(activeUri);
            const password = await vscode.window.showInputBox({
                prompt: "Set password for this workspace/directory",
                password: true,
                placeHolder: "Enter new password (leave empty to clear)",
                ignoreFocusOut: true
            });
            
            if (password === undefined) {
                return; // Cancelled
            }
            
            if (password === "") {
                passwordMap.delete(key);
                vscode.window.showInformationMessage("Password cleared for this directory.");
            } else {
                passwordMap.set(key, password);
                vscode.window.showInformationMessage(
                    "Password set for current session. Note: Existing files on disk are NOT re-encrypted. " +
                    "Use 'V.enc: Change Password & Re-encrypt Files' to update them on disk.",
                    "Got it"
                );
            }
            updateStatusBar();
            
            // Force VS Code to reload open files to apply the new password (clearing cache)
            await reloadWorkspaceVEncFiles();
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('v-enc.openWorkspace', async () => {
            const folders = vscode.workspace.workspaceFolders;
            if (!folders || folders.length === 0) {
                vscode.window.showWarningMessage("No workspace folder open to secure.");
                return;
            }
            
            const currentFolder = folders[0].uri;
            if (currentFolder.scheme === 'venc') {
                vscode.window.showInformationMessage("Workspace is already running in V.enc secure mode.");
                return;
            }
            
            const vencFolderUri = currentFolder.with({ scheme: 'venc' });
            
            // Cache password first
            const password = await getPasswordForUri(vencFolderUri, true);
            if (!password) {
                vscode.window.showWarningMessage("V.enc workspace requires a password to open.");
                return;
            }
            
            await vscode.commands.executeCommand('vscode.openFolder', vencFolderUri, false);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('v-enc.changePassword', async () => {
            let activeUri: vscode.Uri | undefined;
            if (vscode.window.activeTextEditor) {
                activeUri = vscode.window.activeTextEditor.document.uri;
            } else if (vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0) {
                activeUri = vscode.workspace.workspaceFolders[0].uri;
            }
            
            if (!activeUri) {
                vscode.window.showWarningMessage("No active workspace or file to change password for.");
                return;
            }
            
            const key = getDirectoryKey(activeUri);
            
            // 1. Get old password
            let oldPassword = passwordMap.get(key);
            if (!oldPassword) {
                oldPassword = await vscode.window.showInputBox({
                    prompt: "Enter current password to authorize re-encryption",
                    password: true,
                    placeHolder: "Current Password",
                    ignoreFocusOut: true
                });
                if (!oldPassword) {
                    return; // Cancelled
                }
            }
            
            // 2. Get new password
            const newPassword = await vscode.window.showInputBox({
                prompt: "Enter new password for files in this directory",
                password: true,
                placeHolder: "New Password",
                ignoreFocusOut: true
            });
            if (!newPassword) {
                return; // Cancelled
            }
            
            if (newPassword === oldPassword) {
                vscode.window.showWarningMessage("New password is identical to the current password.");
                return;
            }
            
            // 3. Find files
            let fileUris: vscode.Uri[] = [];
            const workspaceFolder = vscode.workspace.getWorkspaceFolder(activeUri.with({ scheme: 'file' }));
            if (workspaceFolder) {
                // Find all .venc files in the workspace folder
                fileUris = await vscode.workspace.findFiles(new vscode.RelativePattern(workspaceFolder, '**/*.venc'));
            } else if (activeUri.path.toLowerCase().endsWith('.venc')) {
                // Just the active file
                fileUris = [activeUri];
            }
            
            if (fileUris.length === 0) {
                vscode.window.showInformationMessage("No .venc files found to re-encrypt.");
                return;
            }
            
            let successCount = 0;
            let failCount = 0;
            const failedFiles: string[] = [];
            
            await vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: "Re-encrypting files...",
                cancellable: false
            }, async () => {
                for (let fileUri of fileUris) {
                    // Always convert to local file scheme for low-level filesystem access
                    fileUri = fileUri.with({ scheme: 'file' });
                    try {
                        const content = await vscode.workspace.fs.readFile(fileUri);
                        if (content.length === 0) {
                            const encrypted = encrypt("", newPassword);
                            await vscode.workspace.fs.writeFile(fileUri, encrypted);
                            successCount++;
                            continue;
                        }
                        
                        const magic = Buffer.from('VENC');
                        if (content.length < magic.length || !Buffer.from(content).subarray(0, magic.length).equals(magic)) {
                            // Plaintext file, encrypt it with new password
                            const plaintext = Buffer.from(content).toString('utf8');
                            const encrypted = encrypt(plaintext, newPassword);
                            await vscode.workspace.fs.writeFile(fileUri, encrypted);
                            successCount++;
                            continue;
                        }
                        
                        // Decrypt with old password
                        const plaintext = decrypt(Buffer.from(content), oldPassword!);
                        
                        // Encrypt with new password
                        const encrypted = encrypt(plaintext, newPassword);
                        await vscode.workspace.fs.writeFile(fileUri, encrypted);
                        successCount++;
                    } catch (err) {
                        failCount++;
                        failedFiles.push(path.basename(fileUri.fsPath));
                    }
                }
            });
            
            // 4. Update the password map
            passwordMap.set(key, newPassword);
            updateStatusBar();
            
            // 5. Notify the user
            if (failCount === 0) {
                vscode.window.showInformationMessage(`Successfully re-encrypted ${successCount} file(s) with the new password.`);
            } else {
                vscode.window.showWarningMessage(
                    `Re-encryption finished: ${successCount} file(s) succeeded, ${failCount} file(s) failed. ` +
                    `Failed files: ${failedFiles.join(', ')}`
                );
            }
        })
    );

    // Create Status Bar Item
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.command = 'v-enc.setPassword';
    context.subscriptions.push(statusBarItem);
    statusBarItem.show();

    // Event listeners
    context.subscriptions.push(
        vscode.window.onDidChangeActiveTextEditor(editor => {
            redirectIfNeeded(editor);
            updateStatusBar();
        })
    );

    context.subscriptions.push(
        vscode.workspace.onDidOpenTextDocument(document => {
            const editor = vscode.window.activeTextEditor;
            if (editor && editor.document === document) {
                redirectIfNeeded(editor);
            }
        })
    );

    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(document => {
            encryptAndRedirectOnSave(document);
        })
    );

    context.subscriptions.push(
        vscode.workspace.onDidChangeWorkspaceFolders(() => {
            updateStatusBar();
        })
    );

    // Initial runs
    if (vscode.window.activeTextEditor) {
        redirectIfNeeded(vscode.window.activeTextEditor);
    }
    updateStatusBar();
}

export function deactivate() {}
