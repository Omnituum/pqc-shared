/**
 * Safe Kyber ML-KEM-768 adapter.
 *
 * Object parameters + branded types.
 */

import { toB64, fromB64 } from '../primitives'
import {
  kyberEncapsulate as rawEncapsulate,
  kyberDecapsulate as rawDecapsulate,
  generateKyberKeypair as rawKeygen,
} from '../kyber'
import type {
  KyberKeyPair,
  KyberEncapsulationKey,
  KyberDecapsulationKey,
  KyberCiphertext,
  KyberEncapsulation,
  SharedSecret,
} from './types'

export async function keygen(): Promise<KyberKeyPair | null> {
  const kp = await rawKeygen()
  if (!kp) return null
  return {
    encapsulationKey: fromB64(kp.publicB64) as KyberEncapsulationKey,
    decapsulationKey: fromB64(kp.secretB64) as KyberDecapsulationKey,
  }
}

export async function encapsulate(params: {
  encapsulationKey: KyberEncapsulationKey
}): Promise<KyberEncapsulation> {
  const result = await rawEncapsulate(toB64(params.encapsulationKey))
  return {
    ciphertext: result.ciphertext as KyberCiphertext,
    sharedSecret: result.sharedSecret as SharedSecret,
  }
}

export async function decapsulate(params: {
  ciphertext: KyberCiphertext
  decapsulationKey: KyberDecapsulationKey
}): Promise<SharedSecret> {
  const ss = await rawDecapsulate(toB64(params.ciphertext), toB64(params.decapsulationKey))
  return ss as SharedSecret
}
