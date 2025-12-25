/**
 * Omnituum Tunnel v1 - Session Implementation
 *
 * XChaCha20-Poly1305 encrypted tunnel with counter-based nonces.
 * Handshake-agnostic: accepts any TunnelKeyMaterial producer.
 *
 * @see pqc-docs/specs/tunnel.v1.md
 */

import { xChaCha20Poly1305Encrypt, xChaCha20Poly1305Decrypt } from '../crypto/primitives/chacha';
import { zeroMemory } from '../security';
import type { TunnelKeyMaterial, PQCTunnelSession } from './types';
import { TUNNEL_KEY_SIZE, TUNNEL_NONCE_SIZE } from './types';

// ═══════════════════════════════════════════════════════════════════════════
// NONCE DERIVATION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Derive a unique nonce from base nonce and counter.
 *
 * Construction:
 * - nonce[0..16] = base[0..16]
 * - nonce[16..24] = base[16..24] XOR BE64(counter)
 *
 * This ensures:
 * - Unique nonces for each message (counter monotonicity)
 * - Different nonces for send/recv (different base nonces)
 * - No nonce reuse until counter overflow (~18 quintillion messages)
 */
function deriveNonce(base: Uint8Array, counter: bigint): Uint8Array {
  const nonce = new Uint8Array(24);

  // Copy first 16 bytes unchanged
  nonce.set(base.subarray(0, 16), 0);

  // XOR counter (big-endian) into last 8 bytes
  const view = new DataView(nonce.buffer, 16, 8);
  const baseView = new DataView(base.buffer, base.byteOffset + 16, 8);

  // Read base's last 8 bytes as bigint and XOR with counter
  const baseValue = baseView.getBigUint64(0, false);
  view.setBigUint64(0, baseValue ^ counter, false);

  return nonce;
}

// ═══════════════════════════════════════════════════════════════════════════
// VALIDATION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Validate tunnel key material.
 */
function validateKeyMaterial(keys: TunnelKeyMaterial): void {
  if (!keys.sendKey || keys.sendKey.length !== TUNNEL_KEY_SIZE) {
    throw new Error(`sendKey must be ${TUNNEL_KEY_SIZE} bytes`);
  }
  if (!keys.recvKey || keys.recvKey.length !== TUNNEL_KEY_SIZE) {
    throw new Error(`recvKey must be ${TUNNEL_KEY_SIZE} bytes`);
  }
  if (!keys.sendBaseNonce || keys.sendBaseNonce.length !== TUNNEL_NONCE_SIZE) {
    throw new Error(`sendBaseNonce must be ${TUNNEL_NONCE_SIZE} bytes`);
  }
  if (!keys.recvBaseNonce || keys.recvBaseNonce.length !== TUNNEL_NONCE_SIZE) {
    throw new Error(`recvBaseNonce must be ${TUNNEL_NONCE_SIZE} bytes`);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// SESSION FACTORY
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Create a secure tunnel session from key material.
 *
 * @param keys - Key material from handshake (Noise, TLS, etc.)
 * @returns Tunnel session for encrypted communication
 *
 * @example
 * ```ts
 * // From Noise handshake
 * const keys = toTunnelKeyMaterial(noiseState);
 * const tunnel = createTunnelSession(keys);
 *
 * // Send encrypted message
 * const ciphertext = tunnel.encrypt(plaintext);
 * channel.send(ciphertext);
 *
 * // Receive encrypted message
 * const plaintext = tunnel.decrypt(received);
 *
 * // Clean up when done
 * tunnel.close();
 * ```
 */
export function createTunnelSession(keys: TunnelKeyMaterial): PQCTunnelSession {
  validateKeyMaterial(keys);

  // Copy key material to prevent external mutation
  const sendKey = new Uint8Array(keys.sendKey);
  const recvKey = new Uint8Array(keys.recvKey);
  const sendBaseNonce = new Uint8Array(keys.sendBaseNonce);
  const recvBaseNonce = new Uint8Array(keys.recvBaseNonce);

  // Per-direction counters
  let sendCounter = 0n;
  let recvCounter = 0n;

  // Session state
  let closed = false;

  /**
   * Assert tunnel is still open.
   */
  function assertOpen(): void {
    if (closed) {
      throw new Error('Tunnel is closed');
    }
  }

  return {
    encrypt(plaintext: Uint8Array, aad?: Uint8Array): Uint8Array {
      assertOpen();

      // Derive nonce for this message
      const nonce = deriveNonce(sendBaseNonce, sendCounter);

      // Encrypt
      const ciphertext = xChaCha20Poly1305Encrypt(sendKey, nonce, plaintext, aad);

      // Increment counter after successful encryption
      sendCounter++;

      // Zero the nonce (it contained counter information)
      zeroMemory(nonce);

      return ciphertext;
    },

    decrypt(ciphertext: Uint8Array, aad?: Uint8Array): Uint8Array | null {
      assertOpen();

      // Derive nonce for this message
      const nonce = deriveNonce(recvBaseNonce, recvCounter);

      // Decrypt
      const plaintext = xChaCha20Poly1305Decrypt(recvKey, nonce, ciphertext, aad);

      // Increment counter after successful decryption
      // Note: We increment even on failure to stay in sync with sender
      recvCounter++;

      // Zero the nonce
      zeroMemory(nonce);

      return plaintext;
    },

    close(): void {
      if (closed) return;

      closed = true;

      // Securely zero all key material
      zeroMemory(sendKey);
      zeroMemory(recvKey);
      zeroMemory(sendBaseNonce);
      zeroMemory(recvBaseNonce);
    },

    get isOpen(): boolean {
      return !closed;
    },

    get sendCounter(): bigint {
      return sendCounter;
    },

    get recvCounter(): bigint {
      return recvCounter;
    },
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Create key material for testing (deterministic).
 * DO NOT use in production - keys are derived from a simple seed.
 *
 * @internal
 */
export function createTestKeyMaterial(seed: string, isInitiator: boolean): TunnelKeyMaterial {
  // Simple deterministic derivation for testing
  const encoder = new TextEncoder();
  const seedBytes = encoder.encode(seed);

  // Generate 128 bytes of "key material" (very insecure, testing only!)
  const material = new Uint8Array(128);
  for (let i = 0; i < 128; i++) {
    material[i] = (seedBytes[i % seedBytes.length] + i) % 256;
  }

  // Split into key components
  const key1 = material.slice(0, 32);
  const key2 = material.slice(32, 64);
  const nonce1 = material.slice(64, 88);
  const nonce2 = material.slice(88, 112);

  // Assign based on role (initiator/responder swap to ensure symmetry)
  if (isInitiator) {
    return {
      sendKey: key1,
      recvKey: key2,
      sendBaseNonce: nonce1,
      recvBaseNonce: nonce2,
    };
  } else {
    return {
      sendKey: key2,
      recvKey: key1,
      sendBaseNonce: nonce2,
      recvBaseNonce: nonce1,
    };
  }
}
