const crypto = require('crypto');
require('dotenv').config();

class VoteEncryption {
  constructor() {
    this.masterKey = crypto.scryptSync(
      process.env.ENCRYPTION_KEY,
      'voting-system-salt',
      32
    );
  }

  /**
   * Encrypt vote data using AES-256-GCM
   * @param {Object} voteData - The vote data to encrypt
   * @returns {Object} Encrypted data with iv and authTag
   */
  encrypt(voteData) {
    try {
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv('aes-256-gcm', this.masterKey, iv);

      let encrypted = cipher.update(JSON.stringify(voteData), 'utf8', 'hex');
      encrypted += cipher.final('hex');

      const authTag = cipher.getAuthTag();

      return {
        data: encrypted,
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
      };
    } catch (error) {
      console.error('Encryption error:', error);
      throw new Error('Failed to encrypt vote data');
    }
  }

  /**
   * Decrypt vote data using AES-256-GCM
   * @param {Object} encryptedData - The encrypted vote data
   * @returns {Object} Decrypted vote data
   */
  decrypt(encryptedData) {
    try {
      const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        this.masterKey,
        Buffer.from(encryptedData.iv, 'hex')
      );

      decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));

      let decrypted = decipher.update(encryptedData.data, 'hex', 'utf8');
      decrypted += decipher.final('utf8');

      return JSON.parse(decrypted);
    } catch (error) {
      console.error('Decryption error:', error);
      throw new Error('Failed to decrypt vote data');
    }
  }

  /**
   * Generate secure random token
   * @param {Number} length - Token length in bytes
   * @returns {String} Secure random token
   */
  generateSecureToken(length = 32) {
    return crypto.randomBytes(length).toString('hex').toUpperCase();
  }

  /**
   * Hash token for storage (one-way)
   * @param {String} token - Token to hash
   * @returns {String} SHA-256 hash
   */
  hashToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  /**
   * Generate cryptographic proof for votes
   * @param {Object} voteData - Vote data to create proof for
   * @returns {Object} Integrity proofs
   */
  createIntegrityProof(voteData) {
    const dataString = JSON.stringify(voteData);

    const sha256Hash = crypto
      .createHash('sha256')
      .update(dataString)
      .digest('hex');

    const sha512Hash = crypto
      .createHash('sha512')
      .update(sha256Hash)
      .digest('hex');

    const integrityKey = crypto.scryptSync(
      process.env.INTEGRITY_KEY,
      'integrity-salt',
      32
    );

    const hmac = crypto
      .createHmac('sha256', integrityKey)
      .update(dataString)
      .digest('hex');

    return {
      sha256: sha256Hash,
      sha512: sha512Hash,
      hmac: hmac,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Verify integrity of vote data
   * @param {Object} voteData - Original vote data
   * @param {Object} proof - Integrity proof to verify against
   * @returns {Object} Verification results
   */
  verifyIntegrity(voteData, proof) {
    const newProof = this.createIntegrityProof(voteData);

    return {
      sha256Valid: newProof.sha256 === proof.sha256,
      sha512Valid: newProof.sha512 === proof.sha512,
      hmacValid: newProof.hmac === proof.hmac,
      overallValid:
        newProof.sha256 === proof.sha256 &&
        newProof.sha512 === proof.sha512 &&
        newProof.hmac === proof.hmac,
      timestamp: new Date().toISOString(),
    };
  }
}

module.exports = new VoteEncryption();
