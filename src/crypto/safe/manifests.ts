/**
 * Primitive identity manifests.
 *
 * Each manifest declares the expected algorithm name and byte sizes.
 * Used by assertPrimitiveIdentity() to verify that the underlying library
 * is the exact primitive we intended to wrap — not a swapped, compromised,
 * or silently upgraded implementation.
 *
 * This catches:
 * - wrong algorithm resolved behind the same import
 * - changed encoding or key format after a dependency update
 * - supply-chain substitution of a different primitive
 * - silent API drift in key/signature sizes
 */

export interface SignatureManifest {
  readonly algorithm: string
  readonly publicKeyBytes: number
  readonly secretKeyBytes: number
  readonly signatureBytes: number
}

export interface KemManifest {
  readonly algorithm: string
  readonly encapsulationKeyBytes: number
  readonly decapsulationKeyBytes: number
  readonly ciphertextBytes: number
  readonly sharedSecretBytes: number
}

export interface DhManifest {
  readonly algorithm: string
  readonly publicKeyBytes: number
  readonly secretKeyBytes: number
  readonly sharedSecretBytes: number
}

export interface SecretboxManifest {
  readonly algorithm: string
  readonly keyBytes: number
  readonly nonceBytes: number
  readonly tagBytes: number
}

// ---- Concrete manifests for Omnituum's primitives ----

export const ML_DSA_65: SignatureManifest = {
  algorithm: 'ML-DSA-65',
  publicKeyBytes: 1952,
  secretKeyBytes: 4032,
  signatureBytes: 3309,
} as const

export const ML_KEM_768: KemManifest = {
  algorithm: 'ML-KEM-768',
  encapsulationKeyBytes: 1184,
  decapsulationKeyBytes: 2400,
  ciphertextBytes: 1088,
  sharedSecretBytes: 32,
} as const

export const X25519: DhManifest = {
  algorithm: 'X25519',
  publicKeyBytes: 32,
  secretKeyBytes: 32,
  sharedSecretBytes: 32,
} as const

export const XSALSA20_POLY1305: SecretboxManifest = {
  algorithm: 'XSalsa20-Poly1305',
  keyBytes: 32,
  nonceBytes: 24,
  tagBytes: 16,
} as const

// ---- Assertion helpers ----

export function assertSignaturePrimitive(
  noble: {
    keygen(seed?: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array }
    sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array
    verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean
  },
  manifest: SignatureManifest,
): void {
  const msg = new Uint8Array([0xde, 0xad, 0xbe, 0xef])
  const { publicKey, secretKey } = noble.keygen()
  const sig = noble.sign(msg, secretKey)

  if (publicKey.length !== manifest.publicKeyBytes) {
    throw new Error(
      `${manifest.algorithm}: publicKey ${publicKey.length} bytes, expected ${manifest.publicKeyBytes}`,
    )
  }
  if (secretKey.length !== manifest.secretKeyBytes) {
    throw new Error(
      `${manifest.algorithm}: secretKey ${secretKey.length} bytes, expected ${manifest.secretKeyBytes}`,
    )
  }
  if (sig.length !== manifest.signatureBytes) {
    throw new Error(
      `${manifest.algorithm}: signature ${sig.length} bytes, expected ${manifest.signatureBytes}`,
    )
  }
  if (!noble.verify(sig, msg, publicKey)) {
    throw new Error(`${manifest.algorithm}: sign/verify roundtrip failed`)
  }
}

export function assertKemPrimitive(
  noble: {
    keygen(): { publicKey: Uint8Array; secretKey: Uint8Array }
    encapsulate(publicKey: Uint8Array): { ciphertext: Uint8Array; sharedSecret: Uint8Array }
    decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array
  },
  manifest: KemManifest,
): void {
  const { publicKey, secretKey } = noble.keygen()
  const { ciphertext, sharedSecret: ss1 } = noble.encapsulate(publicKey)
  const ss2 = noble.decapsulate(ciphertext, secretKey)

  if (publicKey.length !== manifest.encapsulationKeyBytes) {
    throw new Error(
      `${manifest.algorithm}: encapsulationKey ${publicKey.length} bytes, expected ${manifest.encapsulationKeyBytes}`,
    )
  }
  if (secretKey.length !== manifest.decapsulationKeyBytes) {
    throw new Error(
      `${manifest.algorithm}: decapsulationKey ${secretKey.length} bytes, expected ${manifest.decapsulationKeyBytes}`,
    )
  }
  if (ciphertext.length !== manifest.ciphertextBytes) {
    throw new Error(
      `${manifest.algorithm}: ciphertext ${ciphertext.length} bytes, expected ${manifest.ciphertextBytes}`,
    )
  }
  if (ss1.length !== manifest.sharedSecretBytes) {
    throw new Error(
      `${manifest.algorithm}: sharedSecret ${ss1.length} bytes, expected ${manifest.sharedSecretBytes}`,
    )
  }
  if (ss2.length !== manifest.sharedSecretBytes) {
    throw new Error(
      `${manifest.algorithm}: decapsulated sharedSecret ${ss2.length} bytes, expected ${manifest.sharedSecretBytes}`,
    )
  }
  for (let i = 0; i < ss1.length; i++) {
    if (ss1[i] !== ss2[i]) {
      throw new Error(`${manifest.algorithm}: encap/decap shared secrets differ at byte ${i}`)
    }
  }
}

export function assertDhPrimitive(
  noble: {
    getPublicKey(secretKey: Uint8Array): Uint8Array
    getSharedSecret(secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array
    utils: { randomPrivateKey(): Uint8Array }
  },
  manifest: DhManifest,
): void {
  const sk = noble.utils.randomPrivateKey()
  const pk = noble.getPublicKey(sk)

  if (pk.length !== manifest.publicKeyBytes) {
    throw new Error(
      `${manifest.algorithm}: publicKey ${pk.length} bytes, expected ${manifest.publicKeyBytes}`,
    )
  }
  if (sk.length !== manifest.secretKeyBytes) {
    throw new Error(
      `${manifest.algorithm}: secretKey ${sk.length} bytes, expected ${manifest.secretKeyBytes}`,
    )
  }

  // Generate second keypair, compute shared secret both ways
  const sk2 = noble.utils.randomPrivateKey()
  const pk2 = noble.getPublicKey(sk2)
  const ss1 = noble.getSharedSecret(sk, pk2)
  const ss2 = noble.getSharedSecret(sk2, pk)

  if (ss1.length !== manifest.sharedSecretBytes) {
    throw new Error(
      `${manifest.algorithm}: sharedSecret ${ss1.length} bytes, expected ${manifest.sharedSecretBytes}`,
    )
  }
  for (let i = 0; i < ss1.length; i++) {
    if (ss1[i] !== ss2[i]) {
      throw new Error(`${manifest.algorithm}: DH commutativity check failed at byte ${i}`)
    }
  }
}
