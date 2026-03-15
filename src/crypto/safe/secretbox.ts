/**
 * Safe secretbox (xsalsa20-poly1305) adapter.
 *
 * Object parameters + branded types.
 */

import { secretboxRaw, secretboxOpenRaw } from '../nacl'
import type { SymmetricKey, Nonce } from './types'

export function seal(params: {
  key: SymmetricKey
  plaintext: Uint8Array
  nonce: Nonce
}): Uint8Array {
  return secretboxRaw(params.key, params.plaintext, params.nonce)
}

export function open(params: {
  key: SymmetricKey
  ciphertext: Uint8Array
  nonce: Nonce
}): Uint8Array | null {
  return secretboxOpenRaw(params.key, params.ciphertext, params.nonce)
}
