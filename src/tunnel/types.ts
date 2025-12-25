/**
 * Omnituum Tunnel v1 - Type Definitions
 *
 * Post-handshake encrypted tunnel interface.
 * Handshake-agnostic: any key agreement can feed into this.
 *
 * @see pqc-docs/specs/tunnel.v1.md
 */

// ═══════════════════════════════════════════════════════════════════════════
// KEY MATERIAL
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Key material required to establish a tunnel session.
 * Produced by any key agreement protocol (Noise, TLS, custom).
 */
export interface TunnelKeyMaterial {
  /** 32-byte key for outgoing messages */
  sendKey: Uint8Array;

  /** 32-byte key for incoming messages */
  recvKey: Uint8Array;

  /** 24-byte base nonce for outgoing messages */
  sendBaseNonce: Uint8Array;

  /** 24-byte base nonce for incoming messages */
  recvBaseNonce: Uint8Array;
}

// ═══════════════════════════════════════════════════════════════════════════
// SESSION INTERFACE
// ═══════════════════════════════════════════════════════════════════════════

/**
 * A secure tunnel session for post-handshake communication.
 *
 * @example
 * ```ts
 * import { createTunnelSession } from '@omnituum/pqc-shared';
 *
 * const tunnel = createTunnelSession(keys);
 *
 * // Send a message
 * const ciphertext = tunnel.encrypt(plaintext);
 *
 * // Receive a message
 * const plaintext = tunnel.decrypt(ciphertext);
 * if (!plaintext) throw new Error('Authentication failed');
 *
 * // Clean up
 * tunnel.close();
 * ```
 */
export interface PQCTunnelSession {
  /**
   * Encrypt plaintext for transmission.
   * Automatically increments the send counter.
   *
   * @param plaintext - Data to encrypt
   * @param aad - Optional additional authenticated data
   * @returns Ciphertext with authentication tag
   * @throws Error if tunnel is closed
   */
  encrypt(plaintext: Uint8Array, aad?: Uint8Array): Uint8Array;

  /**
   * Decrypt received ciphertext.
   * Automatically increments the receive counter.
   *
   * @param ciphertext - Data to decrypt (includes auth tag)
   * @param aad - Optional additional authenticated data (must match encryption)
   * @returns Plaintext, or null if authentication fails
   * @throws Error if tunnel is closed
   */
  decrypt(ciphertext: Uint8Array, aad?: Uint8Array): Uint8Array | null;

  /**
   * Securely close the tunnel.
   * Zeros all key material and rejects further operations.
   */
  close(): void;

  /**
   * Check if the tunnel is still open.
   */
  readonly isOpen: boolean;

  /**
   * Get current send counter (for debugging/monitoring).
   */
  readonly sendCounter: bigint;

  /**
   * Get current receive counter (for debugging/monitoring).
   */
  readonly recvCounter: bigint;
}

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

/** Tunnel version string */
export const TUNNEL_VERSION = 'omnituum.tunnel.v1' as const;

/** Key size in bytes (32 = 256 bits) */
export const TUNNEL_KEY_SIZE = 32;

/** Base nonce size in bytes (24 for XChaCha20) */
export const TUNNEL_NONCE_SIZE = 24;

/** Authentication tag size in bytes (16 for Poly1305) */
export const TUNNEL_TAG_SIZE = 16;
