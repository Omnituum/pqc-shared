/**
 * Safe Dilithium ML-DSA-65 adapter.
 *
 * Object parameters + branded types = argument inversion is impossible.
 * Includes invariant self-test that runs on first use.
 */

import type {
  DilithiumKeyPair,
  DilithiumSecretKey,
  DilithiumPublicKey,
  DilithiumSignature,
  Message,
} from './types'

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
 * Run once on first use. Verifies that noble's sign/verify argument order
 * matches our wrapper. Throws immediately if the adapter is broken.
 */
async function checkInvariant(): Promise<void> {
  if (_invariantChecked) return
  const mod = await load()

  const msg = new Uint8Array([0xde, 0xad, 0xbe, 0xef])
  const kp = mod.keygen()
  const sig = mod.sign(msg, kp.secretKey)

  if (!mod.verify(sig, msg, kp.publicKey)) {
    throw new Error(
      'CRITICAL: Dilithium adapter invariant failure — noble API argument order may have changed',
    )
  }

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
