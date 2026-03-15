/**
 * High-assurance adapter factories.
 *
 * Single-boundary, typed, invariant-checked.
 * Each factory wraps a low-level positional API into a safe object-parameter API.
 * Branded types prevent argument confusion at compile time.
 * Lazy invariant checks catch API drift at runtime.
 */

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

export function makeSignatureAdapter<Alg extends string>(noble: NobleSigLike, _alg: Alg) {
  let checked = false

  function ensureInvariant() {
    if (checked) return
    const msg = new Uint8Array([0xde, 0xad, 0xbe, 0xef])
    const kp = noble.keygen()
    const sig = noble.sign(msg, kp.secretKey)
    if (!noble.verify(sig, msg, kp.publicKey)) {
      throw new Error(`${_alg} signature adapter invariant failed`)
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

export function makeKemAdapter<Alg extends string>(noble: NobleKemLike, _alg: Alg) {
  let checked = false

  function ensureInvariant() {
    if (checked) return
    const kp = noble.keygen()
    const { ciphertext, sharedSecret: ss1 } = noble.encapsulate(kp.publicKey)
    const ss2 = noble.decapsulate(ciphertext, kp.secretKey)
    if (ss1.length !== ss2.length) {
      throw new Error(`${_alg} KEM adapter invariant failed`)
    }
    for (let i = 0; i < ss1.length; i++) {
      if (ss1[i] !== ss2[i]) throw new Error(`${_alg} KEM adapter invariant failed`)
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

export function makeDhAdapter<Alg extends string>(noble: NobleDhLike, _alg: Alg) {
  return {
    keygen(): { publicKey: DhPublicKey<Alg>; secretKey: DhSecretKey<Alg> } {
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
      return noble.getSharedSecret(params.ourSecretKey, params.theirPublicKey) as DhSharedSecret
    },
  }
}

// ---- Secretbox adapter ----

export type BoxKey = Brand<Uint8Array, 'BoxKey'>
export type BoxNonce = Brand<Uint8Array, 'BoxNonce'>

export type SecretboxLike = {
  (key: Uint8Array, plaintext: Uint8Array, nonce: Uint8Array): Uint8Array
  open(key: Uint8Array, ciphertext: Uint8Array, nonce: Uint8Array): Uint8Array | null
}

export function makeSecretboxAdapter(sealFn: SecretboxLike['open'] extends never ? never : {
  seal: (key: Uint8Array, plaintext: Uint8Array, nonce: Uint8Array) => Uint8Array
  open: (key: Uint8Array, ciphertext: Uint8Array, nonce: Uint8Array) => Uint8Array | null
}) {
  return {
    seal(params: { key: BoxKey; plaintext: Uint8Array; nonce: BoxNonce }): Uint8Array {
      return sealFn.seal(params.key, params.plaintext, params.nonce)
    },

    open(params: { key: BoxKey; ciphertext: Uint8Array; nonce: BoxNonce }): Uint8Array | null {
      return sealFn.open(params.key, params.ciphertext, params.nonce)
    },
  }
}

export function asBoxKey(v: Uint8Array): BoxKey {
  return v as BoxKey
}

export function asBoxNonce(v: Uint8Array): BoxNonce {
  return v as BoxNonce
}
