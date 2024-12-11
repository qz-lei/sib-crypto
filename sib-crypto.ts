import crypto, { KeyObject } from 'node:crypto';

type KeyOutputType = 'hex' | 'base64' | 'buffer';

interface KeyOptions {
  length?: number;
  type?: KeyOutputType;
  iv?: boolean;
}

/**
 * Generates an MD5 hash for a given input message.
 * @param message - The input message to be hashed.
 * @returns The MD5 hash of the input message as a hexadecimal string.
 */
export function md5(message: crypto.BinaryLike): string {
  return crypto.createHash('md5').update(message).digest('hex');
}

/**
 * Encrypts a given message using AES-256-CBC encryption.
 * @param message - The plaintext message to be encrypted.
 * @param key - The secret key used for encryption.
 * @param iv - The initialization vector used for encryption.
 * @returns The encrypted ciphertext as a string.
 */
export function aesEncrypt(message: string, key: string, iv: string) {
  const ivBuffer = Buffer.from(iv);
  if (ivBuffer.length !== 16) {
    throw new Error('IV must be 16 bytes long');
  }
  const cipher = crypto.createCipheriv(
    'aes-256-cbc',
    Buffer.from(key),
    ivBuffer,
  );
  let encrypted = cipher.update(message, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

/**
 * Decrypts a given ciphertext using AES-256-CBC decryption.
 * @param ciphertext - The ciphertext to be decrypted.
 * @param key - The secret key used for decryption.
 * @param iv - The initialization vector used for decryption.
 * @returns The decrypted plaintext as a string.
 */
export function aesDecrypt(ciphertext: string, key: string, iv: string) {
  const ivBuffer = Buffer.from(iv);
  if (ivBuffer.length !== 16) {
    throw new Error('IV must be 16 bytes long');
  }
  const decipher = crypto.createDecipheriv(
    'aes-256-cbc',
    Buffer.from(key),
    ivBuffer,
  );
  let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

/**
 * Encrypts a given message using RSA encryption with the provided public key.
 * @param message - The plaintext message to be encrypted.
 * @param publicKey - The public key used for encryption.
 * @returns The encrypted message as a base64 encoded string.
 */
export function rsaEncrypt(message: string, publicKey: string) {
  const buffer = Buffer.from(message, 'utf-8');
  const encrypted = crypto.publicEncrypt(publicKey, buffer);
  return encrypted.toString('base64');
}

/**
 * Decrypts a given ciphertext using RSA decryption with the provided private key.
 * @param ciphertext - The ciphertext to be decrypted.
 * @param privateKey - The private key used for decryption.
 * @returns The decrypted plaintext as a string.
 */
export function rsaDecrypt(ciphertext: string, privateKey: string | KeyObject) {
  const buffer = Buffer.from(ciphertext, 'base64');
  const decrypted = crypto.privateDecrypt(privateKey, buffer);
  return decrypted.toString('utf-8');
}

/**
 * Decrypts an encrypted private key with the provided password.
 * @param encryptedPrivateKey - The encrypted private key to be decrypted.
 * @param password - The password used for decryption.
 * @returns The decrypted private key as a buffer.
 */
export function decryptPrivateKey(
  encryptedPrivateKey: string,
  password: string,
): KeyObject {
  const buffer = Buffer.from(encryptedPrivateKey);
  const key = crypto.createPrivateKey({
    key: buffer,
    format: 'pem',
    passphrase: password,
  });
  // return key.export({ format: 'pem', type: 'pkcs1' }).toString('utf8');
  return key;
}

/**
 * Generates a random key or IV with the given options.
 * @param {KeyOptions} [options] - Configuration options.
 * @returns {string | Buffer} - The generated key or IV.
 * @property {number} [options.length=32] - The length of the key in bytes.
 * @property {string} [options.type="hex"] - The output format of the key.
 *   Can be "buffer", "base64", or "hex". Defaults to "hex".
 * @property {boolean} [options.iv=false] - Whether to generate an IV (16 bytes)
 *   instead of a key.
 */
export function generateKey(options: KeyOptions = {}): string | Buffer {
  const { length = 32, type = 'hex', iv = false } = options;
  const keyLength = iv ? 16 : length;
  const key = crypto.randomBytes(keyLength);
  switch (type) {
    case 'buffer':
      return key;
    case 'base64':
      return key.toString('base64');
    case 'hex':
    default:
      return key.toString('hex');
  }
}
