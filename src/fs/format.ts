/**
 * Omnituum FS - OQE Binary Format
 *
 * Reader/writer for the .oqe (Omnituum Quantum Encrypted) file format.
 * Implements a documented, stable binary format for encrypted files.
 */

import { textEncoder, textDecoder } from '../crypto/primitives';
import {
  OQE_MAGIC,
  OQE_FORMAT_VERSION,
  OQE_HEADER_SIZE,
  ALGORITHM_SUITES,
  AlgorithmSuiteId,
  OQEHeader,
  OQEMetadata,
  HybridKeyMaterial,
  PasswordKeyMaterial,
  OQEError,
} from './types';

// ═══════════════════════════════════════════════════════════════════════════
// BINARY UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

function writeUint32BE(value: number): Uint8Array {
  const buffer = new ArrayBuffer(4);
  new DataView(buffer).setUint32(0, value, false);
  return new Uint8Array(buffer);
}

function readUint32BE(data: Uint8Array, offset: number): number {
  return new DataView(data.buffer, data.byteOffset + offset).getUint32(0, false);
}

function writeUint16BE(value: number): Uint8Array {
  const buffer = new ArrayBuffer(2);
  new DataView(buffer).setUint16(0, value, false);
  return new Uint8Array(buffer);
}

function readUint16BE(data: Uint8Array, offset: number): number {
  return new DataView(data.buffer, data.byteOffset + offset).getUint16(0, false);
}

// ═══════════════════════════════════════════════════════════════════════════
// OQE HEADER OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Write an OQE file header.
 *
 * @param header - Header data
 * @returns 30-byte header buffer
 */
export function writeOQEHeader(header: OQEHeader): Uint8Array {
  const buffer = new Uint8Array(OQE_HEADER_SIZE);
  let offset = 0;

  // Magic bytes (4 bytes)
  buffer.set(OQE_MAGIC, offset);
  offset += 4;

  // Version (1 byte)
  buffer[offset++] = header.version;

  // Algorithm suite (1 byte)
  buffer[offset++] = header.algorithmSuite;

  // Flags (4 bytes, reserved)
  buffer.set(writeUint32BE(header.flags), offset);
  offset += 4;

  // Metadata length (4 bytes)
  buffer.set(writeUint32BE(header.metadataLength), offset);
  offset += 4;

  // Key material length (4 bytes)
  buffer.set(writeUint32BE(header.keyMaterialLength), offset);
  offset += 4;

  // IV (12 bytes)
  buffer.set(header.iv, offset);
  // offset += 12;

  return buffer;
}

/**
 * Parse an OQE file header.
 *
 * @param data - File data (at least 30 bytes)
 * @returns Parsed header
 * @throws OQEError if header is invalid
 */
export function parseOQEHeader(data: Uint8Array): OQEHeader {
  if (data.length < OQE_HEADER_SIZE) {
    throw new OQEError('INVALID_HEADER', `File too small: need ${OQE_HEADER_SIZE} bytes, got ${data.length}`);
  }

  let offset = 0;

  // Validate magic bytes
  const magic = data.slice(0, 4);
  if (!magic.every((b, i) => b === OQE_MAGIC[i])) {
    throw new OQEError('INVALID_MAGIC', 'Not a valid OQE file (invalid magic bytes)');
  }
  offset += 4;

  // Version
  const version = data[offset++];
  if (version !== OQE_FORMAT_VERSION) {
    throw new OQEError('UNSUPPORTED_VERSION', `Unsupported OQE version: ${version}`);
  }

  // Algorithm suite
  const algorithmSuiteRaw = data[offset++];
  if (
    algorithmSuiteRaw !== ALGORITHM_SUITES.HYBRID_X25519_KYBER768_AES256GCM &&
    algorithmSuiteRaw !== ALGORITHM_SUITES.PASSWORD_ARGON2ID_AES256GCM
  ) {
    throw new OQEError('UNSUPPORTED_ALGORITHM', `Unsupported algorithm suite: 0x${algorithmSuiteRaw.toString(16)}`);
  }
  const algorithmSuite = algorithmSuiteRaw as AlgorithmSuiteId;

  // Flags
  const flags = readUint32BE(data, offset);
  offset += 4;

  // Metadata length
  const metadataLength = readUint32BE(data, offset);
  offset += 4;

  // Key material length
  const keyMaterialLength = readUint32BE(data, offset);
  offset += 4;

  // IV
  const iv = data.slice(offset, offset + 12);

  return {
    version,
    algorithmSuite,
    flags,
    metadataLength,
    keyMaterialLength,
    iv,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// KEY MATERIAL SERIALIZATION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Serialize hybrid mode key material.
 *
 * Format:
 * - X25519 ephemeral PK (32 bytes)
 * - X25519 nonce (24 bytes)
 * - X25519 wrapped key length (2 bytes)
 * - X25519 wrapped key (variable)
 * - Kyber ciphertext length (2 bytes)
 * - Kyber ciphertext (variable, ~1088 bytes)
 * - Kyber nonce (24 bytes)
 * - Kyber wrapped key length (2 bytes)
 * - Kyber wrapped key (variable)
 */
export function serializeHybridKeyMaterial(km: HybridKeyMaterial): Uint8Array {
  const parts: Uint8Array[] = [];

  // X25519 ephemeral public key (32 bytes)
  parts.push(km.x25519EphemeralPk);

  // X25519 nonce (24 bytes)
  parts.push(km.x25519Nonce);

  // X25519 wrapped key (length + data)
  parts.push(writeUint16BE(km.x25519WrappedKey.length));
  parts.push(km.x25519WrappedKey);

  // Kyber ciphertext (length + data)
  parts.push(writeUint16BE(km.kyberCiphertext.length));
  parts.push(km.kyberCiphertext);

  // Kyber nonce (24 bytes)
  parts.push(km.kyberNonce);

  // Kyber wrapped key (length + data)
  parts.push(writeUint16BE(km.kyberWrappedKey.length));
  parts.push(km.kyberWrappedKey);

  // Combine all parts
  const totalLength = parts.reduce((sum, p) => sum + p.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }

  return result;
}

/**
 * Parse hybrid mode key material.
 */
export function parseHybridKeyMaterial(data: Uint8Array): HybridKeyMaterial {
  let offset = 0;

  // X25519 ephemeral public key (32 bytes)
  const x25519EphemeralPk = data.slice(offset, offset + 32);
  offset += 32;

  // X25519 nonce (24 bytes)
  const x25519Nonce = data.slice(offset, offset + 24);
  offset += 24;

  // X25519 wrapped key
  const x25519WrappedLen = readUint16BE(data, offset);
  offset += 2;
  const x25519WrappedKey = data.slice(offset, offset + x25519WrappedLen);
  offset += x25519WrappedLen;

  // Kyber ciphertext
  const kyberCtLen = readUint16BE(data, offset);
  offset += 2;
  const kyberCiphertext = data.slice(offset, offset + kyberCtLen);
  offset += kyberCtLen;

  // Kyber nonce (24 bytes)
  const kyberNonce = data.slice(offset, offset + 24);
  offset += 24;

  // Kyber wrapped key
  const kyberWrappedLen = readUint16BE(data, offset);
  offset += 2;
  const kyberWrappedKey = data.slice(offset, offset + kyberWrappedLen);

  return {
    x25519EphemeralPk,
    x25519Nonce,
    x25519WrappedKey,
    kyberCiphertext,
    kyberNonce,
    kyberWrappedKey,
  };
}

/**
 * Serialize password mode key material.
 *
 * Format:
 * - Salt (32 bytes)
 * - Memory cost (4 bytes, KiB)
 * - Time cost (4 bytes)
 * - Parallelism (4 bytes)
 */
export function serializePasswordKeyMaterial(km: PasswordKeyMaterial): Uint8Array {
  const result = new Uint8Array(32 + 4 + 4 + 4);

  result.set(km.salt, 0);
  result.set(writeUint32BE(km.memoryCost), 32);
  result.set(writeUint32BE(km.timeCost), 36);
  result.set(writeUint32BE(km.parallelism), 40);

  return result;
}

/**
 * Parse password mode key material.
 */
export function parsePasswordKeyMaterial(data: Uint8Array): PasswordKeyMaterial {
  return {
    salt: data.slice(0, 32),
    memoryCost: readUint32BE(data, 32),
    timeCost: readUint32BE(data, 36),
    parallelism: readUint32BE(data, 40),
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// METADATA SERIALIZATION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Serialize metadata to JSON bytes.
 */
export function serializeMetadata(metadata: OQEMetadata): Uint8Array {
  const json = JSON.stringify(metadata);
  return textEncoder.encode(json);
}

/**
 * Parse metadata from JSON bytes.
 */
export function parseMetadata(data: Uint8Array): OQEMetadata {
  const json = textDecoder.decode(data);
  return JSON.parse(json);
}

// ═══════════════════════════════════════════════════════════════════════════
// COMPLETE FILE OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════

export interface OQEFileComponents {
  header: OQEHeader;
  keyMaterial: Uint8Array;
  encryptedMetadata: Uint8Array;
  encryptedContent: Uint8Array;
}

/**
 * Assemble a complete OQE file from components.
 */
export function assembleOQEFile(components: OQEFileComponents): Uint8Array {
  const { header, keyMaterial, encryptedMetadata, encryptedContent } = components;

  const headerBytes = writeOQEHeader(header);
  const totalLength =
    headerBytes.length + keyMaterial.length + encryptedMetadata.length + encryptedContent.length;

  const result = new Uint8Array(totalLength);
  let offset = 0;

  result.set(headerBytes, offset);
  offset += headerBytes.length;

  result.set(keyMaterial, offset);
  offset += keyMaterial.length;

  result.set(encryptedMetadata, offset);
  offset += encryptedMetadata.length;

  result.set(encryptedContent, offset);

  return result;
}

/**
 * Parse a complete OQE file into components.
 */
export function parseOQEFile(data: Uint8Array): OQEFileComponents {
  const header = parseOQEHeader(data);

  let offset = OQE_HEADER_SIZE;

  // Key material
  const keyMaterial = data.slice(offset, offset + header.keyMaterialLength);
  offset += header.keyMaterialLength;

  // Encrypted metadata
  const encryptedMetadata = data.slice(offset, offset + header.metadataLength);
  offset += header.metadataLength;

  // Encrypted content (rest of file)
  const encryptedContent = data.slice(offset);

  return {
    header,
    keyMaterial,
    encryptedMetadata,
    encryptedContent,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// FILE EXTENSION HANDLING
// ═══════════════════════════════════════════════════════════════════════════

/** OQE file extension */
export const OQE_EXTENSION = '.oqe';

/**
 * Add .oqe extension to a filename.
 */
export function addOQEExtension(filename: string): string {
  if (filename.toLowerCase().endsWith(OQE_EXTENSION)) {
    return filename;
  }
  return `${filename}${OQE_EXTENSION}`;
}

/**
 * Remove .oqe extension from a filename.
 */
export function removeOQEExtension(filename: string): string {
  if (filename.toLowerCase().endsWith(OQE_EXTENSION)) {
    return filename.slice(0, -OQE_EXTENSION.length);
  }
  return filename;
}

/**
 * Check if a file is an OQE file (by extension or magic bytes).
 */
export function isOQEFile(filenameOrData: string | Uint8Array): boolean {
  if (typeof filenameOrData === 'string') {
    return filenameOrData.toLowerCase().endsWith(OQE_EXTENSION);
  }

  // Check magic bytes
  if (filenameOrData.length < 4) return false;
  return filenameOrData.slice(0, 4).every((b, i) => b === OQE_MAGIC[i]);
}

// ═══════════════════════════════════════════════════════════════════════════
// MIME TYPE
// ═══════════════════════════════════════════════════════════════════════════

/** OQE MIME type */
export const OQE_MIME_TYPE = 'application/x-omnituum-encrypted';

/**
 * Get a display-friendly algorithm name from suite ID.
 */
export function getAlgorithmName(suiteId: AlgorithmSuiteId): string {
  if (suiteId === ALGORITHM_SUITES.HYBRID_X25519_KYBER768_AES256GCM) {
    return 'Hybrid (X25519 + Kyber768 + AES-256-GCM)';
  }
  if (suiteId === ALGORITHM_SUITES.PASSWORD_ARGON2ID_AES256GCM) {
    return 'Password (Argon2id + AES-256-GCM)';
  }
  return `Unknown (0x${(suiteId as number).toString(16)})`;
}
