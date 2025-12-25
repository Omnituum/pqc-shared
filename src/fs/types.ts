/**
 * Omnituum FS - File Encryption Types
 *
 * Type definitions for the .oqe (Omnituum Quantum Encrypted) file format.
 * Supports two encryption modes:
 * - Mode A: Hybrid (X25519 + Kyber768) - for identity-based encryption
 * - Mode B: Password (Argon2id) - for standalone file protection
 */

// ═══════════════════════════════════════════════════════════════════════════
// OQE FILE FORMAT CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

/** Magic bytes: "OQEF" (Omnituum Quantum Encrypted File) */
export const OQE_MAGIC = new Uint8Array([0x4f, 0x51, 0x45, 0x46]);

/** Current format version */
export const OQE_FORMAT_VERSION = 1;

/** Supported encryption modes */
export type OQEMode = 'hybrid' | 'password';

/** Algorithm suite identifiers */
export const ALGORITHM_SUITES = {
  /** Hybrid: X25519 ECDH + Kyber768 KEM + AES-256-GCM */
  HYBRID_X25519_KYBER768_AES256GCM: 0x01,
  /** Password: Argon2id + AES-256-GCM */
  PASSWORD_ARGON2ID_AES256GCM: 0x02,
} as const;

export type AlgorithmSuiteId = typeof ALGORITHM_SUITES[keyof typeof ALGORITHM_SUITES];

// ═══════════════════════════════════════════════════════════════════════════
// ARGON2ID PARAMETERS (OWASP 2024 Recommendations)
// ═══════════════════════════════════════════════════════════════════════════

export interface Argon2idParams {
  /** Memory cost in KiB (default: 65536 = 64MB) */
  memoryCost: number;
  /** Time cost / iterations (default: 3) */
  timeCost: number;
  /** Parallelism (default: 4) */
  parallelism: number;
  /** Output key length in bytes (default: 32 for AES-256) */
  hashLength: number;
  /** Salt length in bytes (default: 32) */
  saltLength: number;
}

/** Default Argon2id parameters - OWASP 2024 recommended */
export const DEFAULT_ARGON2ID_PARAMS: Argon2idParams = {
  memoryCost: 65536, // 64 MB
  timeCost: 3,
  parallelism: 4,
  hashLength: 32,
  saltLength: 32,
};

/** Minimum Argon2id parameters for low-memory environments */
export const MIN_ARGON2ID_PARAMS: Argon2idParams = {
  memoryCost: 19456, // ~19 MB (OWASP minimum)
  timeCost: 2,
  parallelism: 1,
  hashLength: 32,
  saltLength: 32,
};

// ═══════════════════════════════════════════════════════════════════════════
// OQE FILE METADATA
// ═══════════════════════════════════════════════════════════════════════════

export interface OQEMetadata {
  /** Original filename (encrypted in file) */
  filename: string;
  /** Original file size in bytes */
  originalSize: number;
  /** Original MIME type (optional) */
  mimeType?: string;
  /** Encryption timestamp (ISO 8601) */
  encryptedAt: string;
  /** Encryptor identity hash (hybrid mode only) */
  encryptorIdHash?: string;
  /** Recipient identity hash (hybrid mode only) */
  recipientIdHash?: string;
  /** Custom metadata (optional) */
  custom?: Record<string, string>;
}

// ═══════════════════════════════════════════════════════════════════════════
// OQE FILE HEADER (Binary Format)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * OQE Binary Header Layout:
 *
 * Offset | Size | Description
 * -------|------|------------
 * 0      | 4    | Magic bytes "OQEF"
 * 4      | 1    | Format version (1)
 * 5      | 1    | Algorithm suite ID
 * 6      | 4    | Flags (reserved)
 * 10     | 4    | Metadata length (encrypted JSON)
 * 14     | 4    | Key material length
 * 18     | 12   | AES-GCM IV
 * 30     | var  | Key material (mode-specific)
 * ---    | var  | Encrypted metadata (JSON + auth tag)
 * ---    | var  | Encrypted file content (with auth tag)
 */
export interface OQEHeader {
  /** Format version */
  version: number;
  /** Algorithm suite ID */
  algorithmSuite: AlgorithmSuiteId;
  /** Header flags (reserved for future use) */
  flags: number;
  /** Length of encrypted metadata */
  metadataLength: number;
  /** Length of key material section */
  keyMaterialLength: number;
  /** AES-GCM initialization vector */
  iv: Uint8Array;
}

/** Fixed header size in bytes (before variable-length sections) */
export const OQE_HEADER_SIZE = 30;

// ═══════════════════════════════════════════════════════════════════════════
// KEY MATERIAL (Mode-Specific)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Hybrid Mode Key Material:
 * - X25519 ephemeral public key (32 bytes)
 * - X25519 wrapped content key (32 + 16 bytes auth tag = 48 bytes)
 * - X25519 wrap nonce (24 bytes for XSalsa20-Poly1305)
 * - Kyber KEM ciphertext (~1088 bytes for Kyber768)
 * - Kyber wrapped content key (48 bytes)
 * - Kyber wrap nonce (24 bytes)
 */
export interface HybridKeyMaterial {
  /** X25519 ephemeral public key */
  x25519EphemeralPk: Uint8Array;
  /** X25519 wrapped content key (NaCl secretbox) */
  x25519WrappedKey: Uint8Array;
  /** X25519 wrap nonce */
  x25519Nonce: Uint8Array;
  /** Kyber KEM ciphertext */
  kyberCiphertext: Uint8Array;
  /** Kyber wrapped content key (NaCl secretbox) */
  kyberWrappedKey: Uint8Array;
  /** Kyber wrap nonce */
  kyberNonce: Uint8Array;
}

/**
 * Password Mode Key Material:
 * - Argon2id salt (32 bytes)
 * - Argon2id parameters (encoded as 4 bytes each: mem, time, parallelism)
 */
export interface PasswordKeyMaterial {
  /** Argon2id salt */
  salt: Uint8Array;
  /** Argon2id memory cost in KiB */
  memoryCost: number;
  /** Argon2id time cost (iterations) */
  timeCost: number;
  /** Argon2id parallelism */
  parallelism: number;
}

// ═══════════════════════════════════════════════════════════════════════════
// ENCRYPTION/DECRYPTION OPTIONS
// ═══════════════════════════════════════════════════════════════════════════

/** Options for hybrid mode encryption */
export interface HybridEncryptOptions {
  mode: 'hybrid';
  /** Recipient's public keys */
  recipientPublicKeys: {
    x25519PubHex: string;
    kyberPubB64: string;
  };
  /** Sender identity (optional, for metadata) */
  sender?: {
    id: string;
    name?: string;
  };
}

/** Options for password mode encryption */
export interface PasswordEncryptOptions {
  mode: 'password';
  /** User password */
  password: string;
  /** Argon2id parameters (uses defaults if not specified) */
  argon2Params?: Partial<Argon2idParams>;
}

export type EncryptOptions = HybridEncryptOptions | PasswordEncryptOptions;

/** Options for hybrid mode decryption */
export interface HybridDecryptOptions {
  mode: 'hybrid';
  /** Recipient's secret keys */
  recipientSecretKeys: {
    x25519SecHex: string;
    kyberSecB64: string;
  };
}

/** Options for password mode decryption */
export interface PasswordDecryptOptions {
  mode: 'password';
  /** User password */
  password: string;
}

export type DecryptOptions = HybridDecryptOptions | PasswordDecryptOptions;

// ═══════════════════════════════════════════════════════════════════════════
// ENCRYPTION RESULT
// ═══════════════════════════════════════════════════════════════════════════

export interface OQEEncryptResult {
  /** Complete .oqe file as bytes */
  data: Uint8Array;
  /** Suggested filename with .oqe extension */
  filename: string;
  /** File metadata (for UI display) */
  metadata: OQEMetadata;
  /** Encryption mode used */
  mode: OQEMode;
}

export interface OQEDecryptResult {
  /** Decrypted file content */
  data: Uint8Array;
  /** Original filename */
  filename: string;
  /** Original MIME type */
  mimeType?: string;
  /** Original file size */
  originalSize: number;
  /** File metadata */
  metadata: OQEMetadata;
  /** Decryption mode used */
  mode: OQEMode;
}

// ═══════════════════════════════════════════════════════════════════════════
// ERROR TYPES
// ═══════════════════════════════════════════════════════════════════════════

export type OQEErrorCode =
  | 'INVALID_MAGIC'
  | 'UNSUPPORTED_VERSION'
  | 'UNSUPPORTED_ALGORITHM'
  | 'INVALID_HEADER'
  | 'DECRYPTION_FAILED'
  | 'PASSWORD_WRONG'
  | 'KEY_UNWRAP_FAILED'
  | 'INTEGRITY_CHECK_FAILED'
  | 'KYBER_UNAVAILABLE'
  | 'ARGON2_UNAVAILABLE'
  | 'FILE_TOO_LARGE'
  | 'ENCRYPTION_FAILED';

export class OQEError extends Error {
  constructor(
    public code: OQEErrorCode,
    message: string
  ) {
    super(message);
    this.name = 'OQEError';
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// UTILITY TYPES
// ═══════════════════════════════════════════════════════════════════════════

/** Progress callback for large file operations */
export type ProgressCallback = (progress: {
  phase: 'reading' | 'encrypting' | 'decrypting' | 'writing';
  bytesProcessed: number;
  totalBytes: number;
  percent: number;
}) => void;

/** File input types supported */
export type FileInput = File | Blob | Uint8Array | ArrayBuffer;

/** Convert any file input to Uint8Array */
export async function toUint8Array(input: FileInput): Promise<Uint8Array> {
  if (input instanceof Uint8Array) {
    return input;
  }
  if (input instanceof ArrayBuffer) {
    return new Uint8Array(input);
  }
  // File or Blob
  const buffer = await input.arrayBuffer();
  return new Uint8Array(buffer);
}
