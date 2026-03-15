/**
 * Branded cryptographic types.
 *
 * Raw Uint8Array must never cross module boundaries without type branding.
 * These types make argument inversion a compile-time error.
 */

// ---- Dilithium ML-DSA-65 ----

export type DilithiumSecretKey = Uint8Array & { readonly __brand: 'DilithiumSecretKey' }
export type DilithiumPublicKey = Uint8Array & { readonly __brand: 'DilithiumPublicKey' }
export type DilithiumSignature = Uint8Array & { readonly __brand: 'DilithiumSignature' }

export interface DilithiumKeyPair {
  publicKey: DilithiumPublicKey
  secretKey: DilithiumSecretKey
}

// ---- Kyber ML-KEM-768 ----

export type KyberEncapsulationKey = Uint8Array & { readonly __brand: 'KyberEncapsulationKey' }
export type KyberDecapsulationKey = Uint8Array & { readonly __brand: 'KyberDecapsulationKey' }
export type KyberCiphertext = Uint8Array & { readonly __brand: 'KyberCiphertext' }
export type SharedSecret = Uint8Array & { readonly __brand: 'SharedSecret' }

export interface KyberKeyPair {
  encapsulationKey: KyberEncapsulationKey
  decapsulationKey: KyberDecapsulationKey
}

export interface KyberEncapsulation {
  ciphertext: KyberCiphertext
  sharedSecret: SharedSecret
}

// ---- X25519 ----

export type X25519PublicKey = Uint8Array & { readonly __brand: 'X25519PublicKey' }
export type X25519SecretKey = Uint8Array & { readonly __brand: 'X25519SecretKey' }

export interface X25519KeyPair {
  publicKey: X25519PublicKey
  secretKey: X25519SecretKey
}

// ---- Symmetric ----

export type SymmetricKey = Uint8Array & { readonly __brand: 'SymmetricKey' }
export type Nonce = Uint8Array & { readonly __brand: 'Nonce' }
export type Message = Uint8Array & { readonly __brand: 'Message' }

// ---- Branding helpers ----

export function asMessage(data: Uint8Array): Message {
  return data as Message
}

export function asDilithiumSecretKey(data: Uint8Array): DilithiumSecretKey {
  return data as DilithiumSecretKey
}

export function asDilithiumPublicKey(data: Uint8Array): DilithiumPublicKey {
  return data as DilithiumPublicKey
}

export function asKyberEncapsulationKey(data: Uint8Array): KyberEncapsulationKey {
  return data as KyberEncapsulationKey
}

export function asKyberDecapsulationKey(data: Uint8Array): KyberDecapsulationKey {
  return data as KyberDecapsulationKey
}

export function asX25519PublicKey(data: Uint8Array): X25519PublicKey {
  return data as X25519PublicKey
}

export function asX25519SecretKey(data: Uint8Array): X25519SecretKey {
  return data as X25519SecretKey
}

export function asSymmetricKey(data: Uint8Array): SymmetricKey {
  return data as SymmetricKey
}

export function asNonce(data: Uint8Array): Nonce {
  return data as Nonce
}
