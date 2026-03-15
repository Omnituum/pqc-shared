/**
 * High-assurance adapter factories.
 *
 * Single-boundary, typed, invariant-checked, manifest-verified.
 *
 * Each factory wraps a low-level positional API into a safe object-parameter API.
 * - Branded types prevent argument confusion at compile time.
 * - Lazy invariant checks catch API drift at runtime.
 * - Manifest checks verify primitive identity (key/signature sizes) to catch
 *   supply-chain substitution or silent dependency upgrades.
 */

import type { SignatureManifest, KemManifest, DhManifest, SecretboxManifest } from './manifests'

// ---- Generic brand utility ----

type Brand<T, B extends string> = T & { readonly __brand: B }

// ---- Signature adapter ----

export type SigMessage = Brand<Uint8Array, 'SigMessage'>
export type SigPublicKey<Alg extends string> = Brand<Uint8Array, `${Alg}PublicKey`>
export type SigSecretKey<Alg extends string> = Brand<Uint8Array, `${Alg}SecretKey`>
export type SigSignature<Alg extends string> = Brand<Uint8Array, `${Alg}Signature`>

export type NobleSigLike = {
  keygen(seed?: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array }
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array
  verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean
}

export function makeSignatureAdapter<Alg extends string>(
  noble: NobleSigLike,
  manifest: SignatureManifest,
) {
  let checked = false
  const alg = manifest.algorithm

  function ensureInvariant() {
    if (checked) return
    const msg = new Uint8Array([0xde, 0xad, 0xbe, 0xef])
    const { publicKey, secretKey } = noble.keygen()
    const sig = noble.sign(msg, secretKey)

    // Manifest size checks — verify primitive identity
    if (publicKey.length !== manifest.publicKeyBytes) {
      throw new Error(`${alg}: publicKey ${publicKey.length}B, expected ${manifest.publicKeyBytes}B`)
    }
    if (secretKey.length !== manifest.secretKeyBytes) {
      throw new Error(`${alg}: secretKey ${secretKey.length}B, expected ${manifest.secretKeyBytes}B`)
    }
    if (sig.length !== manifest.signatureBytes) {
      throw new Error(`${alg}: signature ${sig.length}B, expected ${manifest.signatureBytes}B`)
    }

    // Behavioral roundtrip
    if (!noble.verify(sig, msg, publicKey)) {
      throw new Error(`${alg}: sign/verify roundtrip failed`)
    }

    checked = true
  }

  return {
    keygen(): { publicKey: SigPublicKey<Alg>; secretKey: SigSecretKey<Alg> } {
      ensureInvariant()
      const kp = noble.keygen()
      return {
        publicKey: kp.publicKey as SigPublicKey<Alg>,
        secretKey: kp.secretKey as SigSecretKey<Alg>,
      }
    },

    sign(params: {
      message: SigMessage
      secretKey: SigSecretKey<Alg>
    }): SigSignature<Alg> {
      ensureInvariant()
      return noble.sign(params.message, params.secretKey) as SigSignature<Alg>
    },

    verify(params: {
      signature: SigSignature<Alg>
      message: SigMessage
      publicKey: SigPublicKey<Alg>
    }): boolean {
      ensureInvariant()
      return noble.verify(params.signature, params.message, params.publicKey)
    },
  }
}

export function asSigMessage(v: Uint8Array): SigMessage {
  return v as SigMessage
}

// ---- KEM adapter ----

export type KemEncapsKey<Alg extends string> = Brand<Uint8Array, `${Alg}EncapsKey`>
export type KemDecapsKey<Alg extends string> = Brand<Uint8Array, `${Alg}DecapsKey`>
export type KemCiphertext<Alg extends string> = Brand<Uint8Array, `${Alg}Ciphertext`>
export type KemSharedSecret = Brand<Uint8Array, 'KemSharedSecret'>

export type NobleKemLike = {
  keygen(): { publicKey: Uint8Array; secretKey: Uint8Array }
  encapsulate(publicKey: Uint8Array): { ciphertext: Uint8Array; sharedSecret: Uint8Array }
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array
}

export function makeKemAdapter<Alg extends string>(
  noble: NobleKemLike,
  manifest: KemManifest,
) {
  let checked = false
  const alg = manifest.algorithm

  function ensureInvariant() {
    if (checked) return
    const { publicKey, secretKey } = noble.keygen()
    const { ciphertext, sharedSecret: ss1 } = noble.encapsulate(publicKey)
    const ss2 = noble.decapsulate(ciphertext, secretKey)

    // Manifest size checks
    if (publicKey.length !== manifest.encapsulationKeyBytes) {
      throw new Error(`${alg}: encapsKey ${publicKey.length}B, expected ${manifest.encapsulationKeyBytes}B`)
    }
    if (secretKey.length !== manifest.decapsulationKeyBytes) {
      throw new Error(`${alg}: decapsKey ${secretKey.length}B, expected ${manifest.decapsulationKeyBytes}B`)
    }
    if (ciphertext.length !== manifest.ciphertextBytes) {
      throw new Error(`${alg}: ciphertext ${ciphertext.length}B, expected ${manifest.ciphertextBytes}B`)
    }
    if (ss1.length !== manifest.sharedSecretBytes) {
      throw new Error(`${alg}: sharedSecret ${ss1.length}B, expected ${manifest.sharedSecretBytes}B`)
    }

    // Behavioral roundtrip
    if (ss2.length !== ss1.length) {
      throw new Error(`${alg}: encap/decap shared secret length mismatch`)
    }
    for (let i = 0; i < ss1.length; i++) {
      if (ss1[i] !== ss2[i]) throw new Error(`${alg}: encap/decap shared secrets differ`)
    }

    checked = true
  }

  return {
    keygen(): { encapsulationKey: KemEncapsKey<Alg>; decapsulationKey: KemDecapsKey<Alg> } {
      ensureInvariant()
      const kp = noble.keygen()
      return {
        encapsulationKey: kp.publicKey as KemEncapsKey<Alg>,
        decapsulationKey: kp.secretKey as KemDecapsKey<Alg>,
      }
    },

    encapsulate(params: {
      encapsulationKey: KemEncapsKey<Alg>
    }): { ciphertext: KemCiphertext<Alg>; sharedSecret: KemSharedSecret } {
      ensureInvariant()
      const result = noble.encapsulate(params.encapsulationKey)
      return {
        ciphertext: result.ciphertext as KemCiphertext<Alg>,
        sharedSecret: result.sharedSecret as KemSharedSecret,
      }
    },

    decapsulate(params: {
      ciphertext: KemCiphertext<Alg>
      decapsulationKey: KemDecapsKey<Alg>
    }): KemSharedSecret {
      ensureInvariant()
      return noble.decapsulate(params.ciphertext, params.decapsulationKey) as KemSharedSecret
    },
  }
}

// ---- DH adapter ----

export type DhPublicKey<Alg extends string> = Brand<Uint8Array, `${Alg}PublicKey`>
export type DhSecretKey<Alg extends string> = Brand<Uint8Array, `${Alg}SecretKey`>
export type DhSharedSecret = Brand<Uint8Array, 'DhSharedSecret'>

export type NobleDhLike = {
  getPublicKey(secretKey: Uint8Array): Uint8Array
  getSharedSecret(secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array
  utils: { randomPrivateKey(): Uint8Array }
}

export function makeDhAdapter<Alg extends string>(
  noble: NobleDhLike,
  manifest: DhManifest,
) {
  let checked = false
  const alg = manifest.algorithm

  function ensureInvariant() {
    if (checked) return
    const sk = noble.utils.randomPrivateKey()
    const pk = noble.getPublicKey(sk)

    if (pk.length !== manifest.publicKeyBytes) {
      throw new Error(`${alg}: publicKey ${pk.length}B, expected ${manifest.publicKeyBytes}B`)
    }
    if (sk.length !== manifest.secretKeyBytes) {
      throw new Error(`${alg}: secretKey ${sk.length}B, expected ${manifest.secretKeyBytes}B`)
    }

    // DH commutativity check
    const sk2 = noble.utils.randomPrivateKey()
    const pk2 = noble.getPublicKey(sk2)
    const ss1 = noble.getSharedSecret(sk, pk2)
    const ss2 = noble.getSharedSecret(sk2, pk)

    if (ss1.length !== manifest.sharedSecretBytes) {
      throw new Error(`${alg}: sharedSecret ${ss1.length}B, expected ${manifest.sharedSecretBytes}B`)
    }
    for (let i = 0; i < ss1.length; i++) {
      if (ss1[i] !== ss2[i]) throw new Error(`${alg}: DH commutativity failed`)
    }

    checked = true
  }

  return {
    keygen(): { publicKey: DhPublicKey<Alg>; secretKey: DhSecretKey<Alg> } {
      ensureInvariant()
      const secretKey = noble.utils.randomPrivateKey()
      const publicKey = noble.getPublicKey(secretKey)
      return {
        publicKey: publicKey as DhPublicKey<Alg>,
        secretKey: secretKey as DhSecretKey<Alg>,
      }
    },

    sharedSecret(params: {
      ourSecretKey: DhSecretKey<Alg>
      theirPublicKey: DhPublicKey<Alg>
    }): DhSharedSecret {
      ensureInvariant()
      return noble.getSharedSecret(params.ourSecretKey, params.theirPublicKey) as DhSharedSecret
    },
  }
}

// ---- Secretbox adapter ----

export type BoxKey = Brand<Uint8Array, 'BoxKey'>
export type BoxNonce = Brand<Uint8Array, 'BoxNonce'>

export function makeSecretboxAdapter(
  impl: {
    seal: (key: Uint8Array, plaintext: Uint8Array, nonce: Uint8Array) => Uint8Array
    open: (key: Uint8Array, ciphertext: Uint8Array, nonce: Uint8Array) => Uint8Array | null
  },
  manifest: SecretboxManifest,
) {
  let checked = false
  const alg = manifest.algorithm

  function ensureInvariant() {
    if (checked) return
    const key = new Uint8Array(manifest.keyBytes)
    crypto.getRandomValues(key)
    const nonce = new Uint8Array(manifest.nonceBytes)
    crypto.getRandomValues(nonce)
    const plaintext = new Uint8Array([0xca, 0xfe, 0xba, 0xbe])

    const ct = impl.seal(key, plaintext, nonce)
    const overhead = ct.length - plaintext.length
    if (overhead !== manifest.tagBytes) {
      throw new Error(`${alg}: overhead ${overhead}B, expected ${manifest.tagBytes}B tag`)
    }

    const pt = impl.open(key, ct, nonce)
    if (!pt || pt.length !== plaintext.length) {
      throw new Error(`${alg}: seal/open roundtrip failed`)
    }
    for (let i = 0; i < plaintext.length; i++) {
      if (pt[i] !== plaintext[i]) throw new Error(`${alg}: seal/open roundtrip mismatch`)
    }

    checked = true
  }

  return {
    seal(params: { key: BoxKey; plaintext: Uint8Array; nonce: BoxNonce }): Uint8Array {
      ensureInvariant()
      return impl.seal(params.key, params.plaintext, params.nonce)
    },

    open(params: { key: BoxKey; ciphertext: Uint8Array; nonce: BoxNonce }): Uint8Array | null {
      ensureInvariant()
      return impl.open(params.key, params.ciphertext, params.nonce)
    },
  }
}

export function asBoxKey(v: Uint8Array): BoxKey {
  return v as BoxKey
}

export function asBoxNonce(v: Uint8Array): BoxNonce {
  return v as BoxNonce
}
