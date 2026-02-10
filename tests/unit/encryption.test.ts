import crypto from 'crypto';
import { encrypt, decrypt } from '../../src/encryption';

describe('Encryption', () => {
  const key = crypto.randomBytes(32);

  test('encrypt and decrypt roundtrip', () => {
    const plaintext = 'hvs.some-vault-wrap-token-abc123';
    const ciphertext = encrypt(plaintext, key);
    const decrypted = decrypt(ciphertext, key);
    expect(decrypted).toBe(plaintext);
  });

  test('ciphertext format: nonce + encrypted + tag', () => {
    const plaintext = 'test-token';
    const ciphertext = encrypt(plaintext, key);
    // At minimum: 12 (nonce) + 1 (min ciphertext) + 16 (tag) = 29
    expect(ciphertext.length).toBeGreaterThanOrEqual(29);
    // First 12 bytes are nonce
    const nonce = ciphertext.subarray(0, 12);
    expect(nonce.length).toBe(12);
  });

  test('different encryptions produce different ciphertexts (random nonce)', () => {
    const plaintext = 'same-token';
    const c1 = encrypt(plaintext, key);
    const c2 = encrypt(plaintext, key);
    expect(c1.equals(c2)).toBe(false);
  });

  test('decrypt fails with wrong key', () => {
    const plaintext = 'secret-token';
    const ciphertext = encrypt(plaintext, key);
    const wrongKey = crypto.randomBytes(32);
    expect(() => decrypt(ciphertext, wrongKey)).toThrow();
  });

  test('decrypt fails with tampered ciphertext', () => {
    const plaintext = 'secret-token';
    const ciphertext = encrypt(plaintext, key);
    // Tamper with a byte in the middle
    ciphertext[15] ^= 0xff;
    expect(() => decrypt(ciphertext, key)).toThrow();
  });

  test('decrypt fails with too-short data', () => {
    const shortData = Buffer.alloc(10);
    expect(() => decrypt(shortData, key)).toThrow('Ciphertext too short');
  });
});
