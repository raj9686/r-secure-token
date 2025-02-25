import crypto from 'crypto';
import sodium from 'libsodium-wrappers';

interface TokenPayload {
  data: any;
  exp: number;
}

interface SecureToken {
  token: string;
  signature: string;
}

class RSecureToken {
  private static ALGORITHM = 'aes-256-gcm';
  private secretKey: Buffer;
  private keyPair: { publicKey: Uint8Array; privateKey: Uint8Array } | null = null;
  private static NONCE_LENGTH = 12;

  constructor(secretKey?: Buffer) {
    this.secretKey = secretKey || crypto.randomBytes(32);
  }

  private async getKeyPair() {
    if (!this.keyPair) {
      await sodium.ready;
      this.keyPair = sodium.crypto_sign_keypair();
    }
    return this.keyPair;
  }

  async generateToken(payload: TokenPayload): Promise<SecureToken> {
    await sodium.ready;

    const nonce = crypto.randomBytes(RSecureToken.NONCE_LENGTH);
    const cipher = crypto.createCipheriv(
      RSecureToken.ALGORITHM,
      this.secretKey,
      nonce
    ) as crypto.CipherGCM;

    let encrypted = cipher.update(JSON.stringify(payload), 'utf8', 'base64');
    encrypted += cipher.final('base64');

    const authTag = cipher.getAuthTag().toString('base64');
    const token = `${nonce.toString('base64')}.${encrypted}.${authTag}`;

    const signature = await this.signToken(token);
    return { token, signature };
  }

  async verifyToken(token: string, signature: string): Promise<TokenPayload | null> {
    await sodium.ready;

    if (!(await this.verifySignature(token, signature))) return null;

    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const nonce = Buffer.from(parts[0], 'base64');
    const encryptedText = parts[1];
    const authTag = Buffer.from(parts[2], 'base64');

    const decipher = crypto.createDecipheriv(
      RSecureToken.ALGORITHM,
      this.secretKey,
      nonce
    ) as crypto.DecipherGCM;

    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encryptedText, 'base64', 'utf8');
    decrypted += decipher.final('utf8');

    const payload: TokenPayload = JSON.parse(decrypted);
    if (Date.now() > payload.exp) return null;

    return payload;
  }

  private async signToken(token: string): Promise<string> {
    const { privateKey } = await this.getKeyPair();
    const signature = sodium.crypto_sign_detached(Buffer.from(token), privateKey);
    return Buffer.from(signature).toString('base64');
  }

  private async verifySignature(token: string, signature: string): Promise<boolean> {
    const { publicKey } = await this.getKeyPair();
    const signatureBytes = Buffer.from(signature, 'base64');
    return sodium.crypto_sign_verify_detached(signatureBytes, Buffer.from(token), publicKey);
  }
}

export default RSecureToken;