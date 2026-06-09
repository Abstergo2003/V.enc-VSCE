import * as assert from 'assert';
import * as crypto from 'crypto';
import {
    encrypt,
    decrypt,
    encryptSsh,
    decryptSsh,
    parseSshRsaToJwk,
    MAGIC,
    MAGIC_SSH
} from '../crypto';

function serializeRsaToSshRsa(publicKey: crypto.KeyObject): string {
    const jwk = publicKey.export({ format: 'jwk' });
    const e = Buffer.from(jwk.e!, 'base64url');
    const n = Buffer.from(jwk.n!, 'base64url');
    
    const typeBuf = Buffer.from('ssh-rsa', 'utf8');
    
    const parts = [typeBuf, e, n];
    const buffers: Buffer[] = [];
    for (const part of parts) {
        const lenBuf = Buffer.alloc(4);
        lenBuf.writeUInt32BE(part.length, 0);
        buffers.push(lenBuf, part);
    }
    const sshRsaBuf = Buffer.concat(buffers);
    return `ssh-rsa ${sshRsaBuf.toString('base64')} test-key`;
}

suite('Crypto Test Suite', () => {
    test('Symmetric Encryption / Decryption', () => {
        const plaintext = 'Hello, Antigravity!';
        const password = 'super-secret-password';
        
        const encrypted = encrypt(plaintext, password);
        assert.ok(encrypted.length > MAGIC.length);
        assert.deepStrictEqual(encrypted.subarray(0, MAGIC.length), MAGIC);
        
        const decrypted = decrypt(encrypted, password);
        assert.strictEqual(decrypted, plaintext);
    });

    test('Symmetric Decryption fails with invalid password', () => {
        const plaintext = 'Hello, Antigravity!';
        const password = 'super-secret-password';
        const wrongPassword = 'wrong-password';
        
        const encrypted = encrypt(plaintext, password);
        assert.throws(() => {
            decrypt(encrypted, wrongPassword);
        });
    });

    test('Symmetric Decryption fails with corrupted data', () => {
        const password = 'password';
        assert.throws(() => {
            decrypt(Buffer.from('invalid-data'), password);
        }, /Missing VENC header/);
    });

    test('SSH-RSA Public Key Parsing and Hybrid Encryption/Decryption', () => {
        // Generate RSA key pair (2048 bit)
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
        });

        // Serialize to ssh-rsa format
        const sshRsaStr = serializeRsaToSshRsa(publicKey);
        
        // Parse public key string to JWK and load it back
        const jwk = parseSshRsaToJwk(sshRsaStr);
        assert.strictEqual(jwk.kty, 'RSA');
        assert.ok(jwk.n);
        assert.ok(jwk.e);

        const loadedPublicKey = crypto.createPublicKey({
            key: jwk,
            format: 'jwk'
        });

        // Test hybrid encryption / decryption
        const plaintext = 'Secure SSH hybrid payload data';
        const encrypted = encryptSsh(plaintext, loadedPublicKey);
        
        assert.deepStrictEqual(encrypted.subarray(0, MAGIC_SSH.length), MAGIC_SSH);

        const decrypted = decryptSsh(encrypted, privateKey);
        assert.strictEqual(decrypted, plaintext);
    });

    test('SSH-RSA Parsing handles options and whitespace', () => {
        const { publicKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
        });
        const sshRsaStr = serializeRsaToSshRsa(publicKey);

        // Test key with options prefix and trailing comment
        const optionsSshRsaStr = `restrict,port-forwarding ${sshRsaStr}`;
        
        // Let's verify parseSshRsaToJwk on this
        const jwk = parseSshRsaToJwk(optionsSshRsaStr);
        assert.strictEqual(jwk.kty, 'RSA');
    });
});
