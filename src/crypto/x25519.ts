/**
 * Omnituum PQC Shared - X25519 Key Exchange
 *
 * Browser-compatible X25519 operations using tweetnacl.
 * Provides key generation, ECDH, and NaCl box operations.
 */

import nacl from 'tweetnacl';
import { rand24, assertLen, toHex, fromHex, b64, ub64, sha256, hkdfSha256, u8 } from './primitives';

// ═══════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════

export interface X25519Keypair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface X25519KeypairHex {
  publicHex: string;
  secretHex: string;
  publicBytes: Uint8Array;
  secretBytes: Uint8Array;
}

export interface ClassicalWrap {
  ephPubKey: string;
  nonce: string;
  boxed: string;
}

// ═══════════════════════════════════════════════════════════════════════════
// KEY GENERATION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Generate a new random X25519 keypair.
 */
export function generateX25519Keypair(): X25519KeypairHex {
  const kp = nacl.box.keyPair();
  return {
    publicHex: '0x' + toHex(kp.publicKey),
    secretHex: '0x' + toHex(kp.secretKey),
    publicBytes: kp.publicKey,
    secretBytes: kp.secretKey,
  };
}

/**
 * Generate a deterministic X25519 keypair from a 32-byte seed.
 */
export function generateX25519KeypairFromSeed(seed: Uint8Array): X25519Keypair {
  if (seed.length !== 32) {
    throw new Error('X25519 seed must be 32 bytes');
  }

  // Hash seed for uniformity
  const uniformSeed = sha256(seed);

  // Generate keypair from secret key
  const kp = nacl.box.keyPair.fromSecretKey(uniformSeed);

  return {
    publicKey: kp.publicKey,
    secretKey: uniformSeed,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// KEY WRAPPING
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Wrap a symmetric key for a recipient using X25519 ECDH.
 * Creates an ephemeral keypair and encrypts the key using NaCl box.
 */
export function boxWrapWithX25519(symKey32: Uint8Array, recipientPubKeyHex: string): ClassicalWrap {
  assertLen('sym key', symKey32, 32);
  const pk = fromHex(recipientPubKeyHex);
  assertLen('recipient pubKey', pk, 32);

  // Generate ephemeral keypair
  const eph = nacl.box.keyPair();
  const nonce = rand24();

  // Encrypt the symmetric key
  const boxed = nacl.box(symKey32, nonce, pk, eph.secretKey);

  return {
    ephPubKey: toHex(eph.publicKey),
    nonce: b64(nonce),
    boxed: b64(boxed),
  };
}

/**
 * Unwrap a symmetric key using X25519 ECDH.
 */
export function boxUnwrapWithX25519(
  wrap: ClassicalWrap,
  recipientSecretKey32: Uint8Array
): Uint8Array | null {
  assertLen('recipient secretKey', recipientSecretKey32, 32);
  const ephPk = fromHex(wrap.ephPubKey);
  assertLen('ephemeral pubKey', ephPk, 32);

  return nacl.box.open(
    ub64(wrap.boxed),
    ub64(wrap.nonce),
    ephPk,
    recipientSecretKey32
  ) || null;
}

/**
 * Perform raw X25519 ECDH to derive a shared secret.
 */
export function x25519SharedSecret(
  ourSecretKey: Uint8Array,
  theirPublicKey: Uint8Array
): Uint8Array {
  assertLen('secret key', ourSecretKey, 32);
  assertLen('public key', theirPublicKey, 32);
  return nacl.scalarMult(ourSecretKey, theirPublicKey);
}

// ═══════════════════════════════════════════════════════════════════════════
// HKDF KEY DERIVATION HELPER
// ═══════════════════════════════════════════════════════════════════════════

export function deriveKeyFromShared(shared: Uint8Array, salt: string, info: string): Uint8Array {
  return hkdfSha256(shared, { salt: u8(salt), info: u8(info), length: 32 });
}
