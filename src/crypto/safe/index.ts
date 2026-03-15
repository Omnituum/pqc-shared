/**
 * @omnituum/pqc-shared/safe — Type-safe crypto adapter layer.
 *
 * All functions use branded types and object parameters.
 * Argument inversion is a compile-time error.
 *
 * Usage:
 *   import { dilithium, kyber, x25519, secretbox } from '@omnituum/pqc-shared/safe'
 *
 *   const kp = await dilithium.keygen()
 *   const sig = await dilithium.sign({ message: msg, secretKey: kp.secretKey })
 *   const ok = await dilithium.verify({ signature: sig, message: msg, publicKey: kp.publicKey })
 */

export * as dilithium from './dilithium'
export * as kyber from './kyber'
export * as x25519 from './x25519'
export * as secretbox from './secretbox'

export type {
  DilithiumSecretKey,
  DilithiumPublicKey,
  DilithiumSignature,
  DilithiumKeyPair,
  KyberEncapsulationKey,
  KyberDecapsulationKey,
  KyberCiphertext,
  KyberKeyPair,
  KyberEncapsulation,
  SharedSecret,
  X25519PublicKey,
  X25519SecretKey,
  X25519KeyPair,
  SymmetricKey,
  Nonce,
  Message,
} from './types'

export {
  asMessage,
  asDilithiumSecretKey,
  asDilithiumPublicKey,
  asKyberEncapsulationKey,
  asKyberDecapsulationKey,
  asX25519PublicKey,
  asX25519SecretKey,
  asSymmetricKey,
  asNonce,
} from './types'

// Adapter factories — for building new type-safe wrappers around any noble-like API
export {
  makeSignatureAdapter,
  makeKemAdapter,
  makeDhAdapter,
  makeSecretboxAdapter,
  asSigMessage,
  asBoxKey,
  asBoxNonce,
} from './adapters'

export type {
  NobleSigLike,
  NobleKemLike,
  NobleDhLike,
  SigMessage,
  SigPublicKey,
  SigSecretKey,
  SigSignature,
  KemEncapsKey,
  KemDecapsKey,
  KemCiphertext,
  KemSharedSecret,
  DhPublicKey,
  DhSecretKey,
  DhSharedSecret,
  BoxKey,
  BoxNonce,
} from './adapters'
