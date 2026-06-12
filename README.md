# V.enc - Transparent File Encryption for VS Code

**V.enc** is a VS Code extension that provides transparent, on-the-fly encryption and decryption for files ending with the `.venc` extension. It ensures that your files are safely encrypted at rest on your local disk, but appear as plain text inside your VS Code editor when authorized.

---

## ✨ Features

- **Transparent Encryption/Decryption**: Open any `.venc` file, unlock it, and edit the plaintext. When you save, V.enc automatically encrypts and signs the file before writing it to disk.
- **Two Encryption Modes**:
  - **Symmetric Mode**: Uses PBKDF2 + AES-256-GCM based on a directory-level password cached in memory.
  - **Asymmetric Mode (SSH Keys)**: Encrypts files using a public SSH key (or standard PEM public key) and decrypts them using the matching private SSH key via secure hybrid envelope encryption.
- **Robust Cryptography**:
  - Symmetric files are encrypted using AES-256-GCM with keys derived using PBKDF2 (100,000 iterations, SHA-256, random salts).
  - Asymmetric files encrypt an ephemeral 256-bit AES symmetric key via RSA-OAEP (SHA-256), and encrypt the file payload using AES-256-GCM with that symmetric key.
- **In-Memory Caching & Passphrase Support**:
  - Passwords and SSH private keys are cached in-memory during the active VS Code session to avoid repeat prompting.
  - Supports passphrase-protected private keys with secure VS Code input prompts.
- **Flicker-Free Secure Workspace Mode**: Reopen your entire workspace under the `venc://` scheme to get a native, flicker-free file tree where all `.venc` files automatically decrypt on click.
- **Seamless Format Migration**: The `V.enc: Change Password & Re-encrypt Files` command migrates your files seamlessly between password-based encryption and SSH-key-based encryption, or updates existing passwords/keys.
- **Custom Premium Icon**: Features a custom-designed dark/light-mode compatible icon for `.venc` files in the file explorer.

---

## 🛠️ Configuration Settings

V.enc adds the following settings to VS Code:

- **`v-enc.encryptionMode`**: Set to `"password"` (default) for directory-password symmetric encryption, or `"sshKey"` for SSH public/private key envelope encryption.
- **`v-enc.sshPublicKeyPath`**: Path to the SSH public key file (defaults to `~/.ssh/id_rsa.pub`). Supports standard `ssh-rsa` public keys or PEM public keys.
- **`v-enc.sshPrivateKeyPath`**: Path to the SSH private key file (defaults to `~/.ssh/id_rsa`). Supports passphrase-protected private keys.

### 🔑 Configuring SSH Keys

To configure the SSH key options, open your VS Code settings (`Ctrl+,` or `Cmd+,`) or edit your `settings.json` file:

#### 1. Path Formatting & Tilde Expansion
The settings support two types of path formatting:
- **Tilde Expansion (`~`)**: The tilde `~` symbol automatically resolves to your system user profile/home directory. This is the most portable format.
  * Public Key Default: `~/.ssh/id_rsa.pub` (resolves to `/Users/username/.ssh/id_rsa.pub` on macOS/Linux or `C:\Users\username\.ssh\id_rsa.pub` on Windows)
  * Private Key Default: `~/.ssh/id_rsa`
- **Absolute Paths**: You can specify absolute paths. On Windows, use forward slashes `/` or escaped backslashes `\\` to avoid syntax errors:
  * Example (Forward Slashes): `C:/Users/YourUsername/.ssh/id_rsa`
  * Example (Backslashes): `C:\\Users\\YourUsername\\.ssh\\id_rsa`

#### 2. Key Format Compatibility
- **Public Key**: Supports standard OpenSSH public key format (e.g. starting with `ssh-rsa AAAAB3...`) and standard PEM public keys (starting with `-----BEGIN PUBLIC KEY-----`).
- **Private Key**: Supports standard PEM-encoded private keys (including OpenSSH private key formats starting with `-----BEGIN OPENSSH PRIVATE KEY-----` or PKCS#1/PKCS#8).
- **Passphrase-Protected Keys**: If your private key requires a passphrase, V.enc displays a secure input field in the VS Code command palette. The passphrase is cached in-memory during the active VS Code session and is never saved to disk.

#### 3. Settings Sync & Privacy
Both SSH key path settings are defined with `machine-overridable` scope. This guarantees that **VS Code's Settings Sync will not sync these paths to the cloud**, keeping your local usernames and key paths private to each physical machine.

---

## 🛠️ Commands

This extension contributes the following commands to the Command Palette:

1. **`V.enc: Set/Change Password for Directory`** (`v-enc.setPassword`):
   - Sets or clears the active session password for the current directory (used in symmetric mode).
2. **`V.enc: Change Password & Re-encrypt Files`** (`v-enc.changePassword`):
   - Updates the password or migrates the workspace `.venc` files to/from SSH key mode based on your current settings.
3. **`V.enc: Reopen Workspace in Secure Mode`** (`v-enc.openWorkspace`):
   - Reopens the current folder as a virtual secure workspace (`venc://` scheme).

---

## 🔒 Security Envelope & Format

V.enc automatically detects the encryption format using magic headers:

### Symmetric Format (`VENC`)
Each password-encrypted `.venc` file on disk contains a payload structured as follows:
- **`0-3` (4 bytes)**: Magic Header `VENC`
- **`4-19` (16 bytes)**: PBKDF2 key derivation salt
- **`20-31` (12 bytes)**: AES-GCM Initialization Vector (IV)
- **`32-47` (16 bytes)**: AES-GCM Authentication Tag
- **`48+` (variable)**: Ciphertext

### Asymmetric Hybrid Format (`VESH`)
Each SSH-key-encrypted `.venc` file on disk contains a payload structured as follows:
- **`0-3` (4 bytes)**: Magic Header `VESH`
- **`4-5` (2 bytes)**: Ephemeral symmetric key length (Big-endian uint16)
- **`6 - (6+keyLength-1)`**: RSA-OAEP encrypted ephemeral symmetric key
- **`Next 12 bytes`**: AES-GCM Initialization Vector (IV)
- **`Next 16 bytes`**: AES-GCM Authentication Tag
- **`Remaining bytes`**: Ciphertext

> [!WARNING]
> Because V.enc does not use a master key recovery mechanism, **lost passwords or private keys are unrecoverable**. Ensure you keep backups of your keys/passwords.

---

## 🚀 Getting Started

### Symmetric (Password) Mode
1. Open a workspace folder in VS Code.
2. Set a password for the folder by clicking the status bar item **`🔒 V.enc: Not Set`** (or run `V.enc: Set/Change Password for Directory` in the Command Palette).
3. Create or rename a file to end with `.venc` (e.g. `secrets.venc`).
4. Type some secret data and save the file. It will be saved as ciphertext on disk but stay decrypted in VS Code.

### Asymmetric (SSH Key) Mode
1. Go to VS Code settings and set **`V-enc: Encryption Mode`** to `sshKey`.
2. Configure **`V-enc: Ssh Public Key Path`** and **`V-enc: Ssh Private Key Path`** (defaults point to standard user SSH paths).
3. Open or create any `.venc` file. The extension will automatically read your public key to encrypt, and prompt you for the private key passphrase (if protected) on decryption.
4. To migrate existing password-encrypted `.venc` files, run **`V.enc: Change Password & Re-encrypt Files`** from the Command Palette.

