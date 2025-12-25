/**
 * Omnituum Tunnel v1
 *
 * Post-handshake encrypted tunnel abstraction.
 * Handshake-agnostic: any key agreement protocol can feed into this.
 *
 * @example
 * ```ts
 * import { createTunnelSession, TunnelKeyMaterial } from '@omnituum/pqc-shared';
 *
 * // From Noise handshake
 * const keys: TunnelKeyMaterial = toTunnelKeyMaterial(noiseState);
 * const tunnel = createTunnelSession(keys);
 *
 * // Encrypt
 * const ciphertext = tunnel.encrypt(plaintext);
 *
 * // Decrypt
 * const plaintext = tunnel.decrypt(ciphertext);
 *
 * // Clean up
 * tunnel.close();
 * ```
 *
 * @see pqc-docs/specs/tunnel.v1.md
 */

// Types
export type { TunnelKeyMaterial, PQCTunnelSession } from './types';

export {
  TUNNEL_VERSION,
  TUNNEL_KEY_SIZE,
  TUNNEL_NONCE_SIZE,
  TUNNEL_TAG_SIZE,
} from './types';

// Session factory
export { createTunnelSession, createTestKeyMaterial } from './session';
