import * as crypto from 'crypto';

export const MAGIC = Buffer.from('VENC');
export const MAGIC_SSH = Buffer.from('VESH');

const SALT_SIZE = 16;
const IV_SIZE = 12;
const TAG_SIZE = 16;
const PBKDF2_ITERATIONS = 100000;

/**
 * Encrypts a plaintext string using AES-256-GCM with a PBKDF2 derived key.
 * Output format: [4 bytes MAGIC] [16 bytes SALT] [12 bytes IV] [16 bytes AUTH TAG] [ciphertext]
 */
export function encrypt(plaintext: string, password: string): Buffer {
    const salt = crypto.randomBytes(SALT_SIZE);
    const iv = crypto.randomBytes(IV_SIZE);
    
    // Derive key
    const key = crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, 32, 'sha256');
    
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    
    const ciphertext = Buffer.concat([
        cipher.update(plaintext, 'utf8'),
        cipher.final()
    ]);
    
    const tag = cipher.getAuthTag();
    
    return Buffer.concat([MAGIC, salt, iv, tag, ciphertext]);
}

/**
 * Decrypts an AES-256-GCM encrypted buffer using a password.
 * Checks for the MAGIC header and verifies authenticity using the GCM auth tag.
 */
export function decrypt(encrypted: Buffer, password: string): string {
    // Check magic
    if (encrypted.length < MAGIC.length || !encrypted.subarray(0, MAGIC.length).equals(MAGIC)) {
        throw new Error('Missing VENC header');
    }
    
    if (encrypted.length < MAGIC.length + SALT_SIZE + IV_SIZE + TAG_SIZE) {
        throw new Error('File is truncated or invalid');
    }
    
    let offset = MAGIC.length;
    const salt = encrypted.subarray(offset, offset + SALT_SIZE);
    offset += SALT_SIZE;
    const iv = encrypted.subarray(offset, offset + IV_SIZE);
    offset += IV_SIZE;
    const tag = encrypted.subarray(offset, offset + TAG_SIZE);
    offset += TAG_SIZE;
    const ciphertext = encrypted.subarray(offset);
    
    // Derive key
    const key = crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, 32, 'sha256');
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    
    const plaintext = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final()
    ]).toString('utf8');
    
    return plaintext;
}

/**
 * Parses an ssh-rsa public key string (e.g. "ssh-rsa AAAAB3Nza...") into a JSON Web Key (JWK) object
 * which Node's crypto module can natively import.
 */
export function parseSshRsaToJwk(sshRsaStr: string): any {
    const parts = sshRsaStr.trim().split(/\s+/);
    const typeIndex = parts.indexOf('ssh-rsa');
    if (typeIndex === -1 || typeIndex + 1 >= parts.length) {
        throw new Error('Invalid SSH public key format: missing ssh-rsa marker or key blob.');
    }
    const base64Part = parts[typeIndex + 1];
    
    const buf = Buffer.from(base64Part, 'base64');
    let offset = 0;
    
    function readBuffer() {
        if (offset + 4 > buf.length) {
            throw new Error('Malformed SSH key buffer');
        }
        const len = buf.readUInt32BE(offset);
        offset += 4;
        if (offset + len > buf.length) {
            throw new Error('Malformed SSH key buffer');
        }
        const res = buf.subarray(offset, offset + len);
        offset += len;
        return res;
    }
    
    const type = readBuffer().toString('utf8');
    if (type !== 'ssh-rsa') {
        throw new Error(`Key type mismatch: expected ssh-rsa, got ${type}`);
    }
    
    const exponent = readBuffer();
    const modulus = readBuffer();
    
    function toBase64Url(buffer: Buffer) {
        return buffer.toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }
    
    return {
        kty: 'RSA',
        n: toBase64Url(modulus),
        e: toBase64Url(exponent)
    };
}

/**
 * Encrypts a plaintext string using hybrid encryption (AES-256-GCM + SSH RSA Public Key).
 * Format: [4 bytes MAGIC_SSH] [2 bytes keyLength] [keyLength bytes encryptedSymmetricKey] [12 bytes IV] [16 bytes GCM auth tag] [ciphertext]
 */
export function encryptSsh(plaintext: string, publicKey: crypto.KeyObject): Buffer {
    const symmetricKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(IV_SIZE);
    
    const cipher = crypto.createCipheriv('aes-256-gcm', symmetricKey, iv);
    const ciphertext = Buffer.concat([
        cipher.update(plaintext, 'utf8'),
        cipher.final()
    ]);
    const tag = cipher.getAuthTag();
    
    const encryptedSymmetricKey = crypto.publicEncrypt({
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
    }, symmetricKey);
    
    const keyLenBuf = Buffer.alloc(2);
    keyLenBuf.writeUInt16BE(encryptedSymmetricKey.length, 0);
    
    return Buffer.concat([
        MAGIC_SSH,
        keyLenBuf,
        encryptedSymmetricKey,
        iv,
        tag,
        ciphertext
    ]);
}

/**
 * Decrypts an AES-256-GCM encrypted buffer using an SSH Private Key.
 */
export function decryptSsh(encrypted: Buffer, privateKey: crypto.KeyObject): string {
    // Check magic
    if (encrypted.length < MAGIC_SSH.length || !encrypted.subarray(0, MAGIC_SSH.length).equals(MAGIC_SSH)) {
        throw new Error('Missing VESH header');
    }
    
    let offset = MAGIC_SSH.length;
    if (encrypted.length < offset + 2) {
        throw new Error('File is truncated (missing key length)');
    }
    
    const keyLength = encrypted.readUInt16BE(offset);
    offset += 2;
    
    if (encrypted.length < offset + keyLength + IV_SIZE + TAG_SIZE) {
        throw new Error('File is truncated or invalid');
    }
    
    const encryptedSymmetricKey = encrypted.subarray(offset, offset + keyLength);
    offset += keyLength;
    const iv = encrypted.subarray(offset, offset + IV_SIZE);
    offset += IV_SIZE;
    const tag = encrypted.subarray(offset, offset + TAG_SIZE);
    offset += TAG_SIZE;
    const ciphertext = encrypted.subarray(offset);
    
    // Decrypt the symmetric key
    const symmetricKey = crypto.privateDecrypt({
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
    }, encryptedSymmetricKey);
    
    // Decrypt the ciphertext
    const decipher = crypto.createDecipheriv('aes-256-gcm', symmetricKey, iv);
    decipher.setAuthTag(tag);
    
    const plaintext = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final()
    ]).toString('utf8');
    
    return plaintext;
}
