import crypto from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const NONCE_LENGTH = 12;
const TAG_LENGTH = 16;

export function encrypt(plaintext: string, key: Buffer): Buffer {
  const nonce = crypto.randomBytes(NONCE_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, nonce);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf-8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  // Format: nonce (12) + ciphertext (variable) + tag (16)
  return Buffer.concat([nonce, encrypted, tag]);
}

export function decrypt(data: Buffer, key: Buffer): string {
  if (data.length < NONCE_LENGTH + TAG_LENGTH) {
    throw new Error('Ciphertext too short');
  }
  const nonce = data.subarray(0, NONCE_LENGTH);
  const tag = data.subarray(data.length - TAG_LENGTH);
  const ciphertext = data.subarray(NONCE_LENGTH, data.length - TAG_LENGTH);
  const decipher = crypto.createDecipheriv(ALGORITHM, key, nonce);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted.toString('utf-8');
}
