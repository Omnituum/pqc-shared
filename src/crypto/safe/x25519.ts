/**
 * Safe X25519 adapter.
 *
 * Object parameters + branded types.
 */

import {
  generateX25519Keypair as rawKeygen,
  x25519SharedSecret as rawEcdh,
} from '../x25519'
import type {
  X25519KeyPair,
  X25519PublicKey,
  X25519SecretKey,
  SharedSecret,
} from './types'

export function keygen(): X25519KeyPair {
  const kp = rawKeygen()
  return {
    publicKey: kp.publicBytes as X25519PublicKey,
    secretKey: kp.secretBytes as X25519SecretKey,
  }
}

export function sharedSecret(params: {
  ourSecretKey: X25519SecretKey
  theirPublicKey: X25519PublicKey
}): SharedSecret {
  return rawEcdh(params.ourSecretKey, params.theirPublicKey) as SharedSecret
}
