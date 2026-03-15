/**
 * Safe Dilithium ML-DSA-65 adapter.
 *
 * Object parameters + branded types + manifest verification.
 * - Argument inversion is a compile-time error.
 * - Primitive identity verified on first use (key/sig sizes match manifest).
 * - Behavioral roundtrip confirmed before any real operation.
 */

import type {
  DilithiumKeyPair,
  DilithiumSecretKey,
  DilithiumPublicKey,
  DilithiumSignature,
  Message,
} from './types'
import { ML_DSA_65, assertSignaturePrimitive } from './manifests'

let _mod: any = null
let _invariantChecked = false

async function load(): Promise<any> {
  if (!_mod) {
    const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js')
    _mod = ml_dsa65
  }
  return _mod
}

/**
 * Run once on first use. Verifies:
 * 1. Key and signature sizes match ML-DSA-65 manifest
 * 2. sign/verify roundtrip produces correct result
 * Catches both argument order bugs and supply-chain primitive substitution.
 */
async function checkInvariant(): Promise<void> {
  if (_invariantChecked) return
  const mod = await load()
  assertSignaturePrimitive(mod, ML_DSA_65)
  _invariantChecked = true
}

export async function keygen(): Promise<DilithiumKeyPair> {
  const mod = await load()
  await checkInvariant()
  const kp = mod.keygen()
  return {
    publicKey: kp.publicKey as DilithiumPublicKey,
    secretKey: kp.secretKey as DilithiumSecretKey,
  }
}

export async function sign(params: {
  message: Message
  secretKey: DilithiumSecretKey
}): Promise<DilithiumSignature> {
  const mod = await load()
  await checkInvariant()
  return mod.sign(params.message, params.secretKey) as DilithiumSignature
}

export async function verify(params: {
  signature: DilithiumSignature
  message: Message
  publicKey: DilithiumPublicKey
}): Promise<boolean> {
  const mod = await load()
  await checkInvariant()
  try {
    return mod.verify(params.signature, params.message, params.publicKey)
  } catch {
    return false
  }
}
