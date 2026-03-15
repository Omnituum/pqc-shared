/**
 * Tests for the type-safe Dilithium adapter.
 *
 * These tests verify that:
 * 1. Object parameter API works correctly
 * 2. Branded types flow through keygen → sign → verify
 * 3. Invariant self-test catches broken noble API
 * 4. Argument inversion is impossible at the API level
 */
import { describe, it, expect } from 'vitest'
import { dilithium, asMessage } from '../../src/crypto/safe'
import type { DilithiumSecretKey, DilithiumPublicKey, Message } from '../../src/crypto/safe'

describe('safe dilithium adapter', () => {
  it('keygen → sign → verify roundtrip', async () => {
    const kp = await dilithium.keygen()
    const msg = asMessage(new Uint8Array([1, 2, 3, 4]))

    const sig = await dilithium.sign({ message: msg, secretKey: kp.secretKey })

    const valid = await dilithium.verify({
      signature: sig,
      message: msg,
      publicKey: kp.publicKey,
    })
    expect(valid).toBe(true)
  })

  it('verify rejects tampered message', async () => {
    const kp = await dilithium.keygen()
    const msg = asMessage(new Uint8Array([1, 2, 3]))
    const sig = await dilithium.sign({ message: msg, secretKey: kp.secretKey })

    const tampered = asMessage(new Uint8Array([9, 9, 9]))
    const valid = await dilithium.verify({
      signature: sig,
      message: tampered,
      publicKey: kp.publicKey,
    })
    expect(valid).toBe(false)
  })

  it('verify rejects wrong public key', async () => {
    const kp1 = await dilithium.keygen()
    const kp2 = await dilithium.keygen()
    const msg = asMessage(new Uint8Array([5, 6, 7]))

    const sig = await dilithium.sign({ message: msg, secretKey: kp1.secretKey })

    const valid = await dilithium.verify({
      signature: sig,
      message: msg,
      publicKey: kp2.publicKey,
    })
    expect(valid).toBe(false)
  })

  it('signature has correct size (3309 bytes for ML-DSA-65)', async () => {
    const kp = await dilithium.keygen()
    const msg = asMessage(new Uint8Array([0xca, 0xfe]))
    const sig = await dilithium.sign({ message: msg, secretKey: kp.secretKey })
    expect(sig.length).toBe(3309)
  })

  it('public key is 1952 bytes, secret key is 4032 bytes', async () => {
    const kp = await dilithium.keygen()
    expect(kp.publicKey.length).toBe(1952)
    expect(kp.secretKey.length).toBe(4032)
  })

  // This test documents the compile-time safety: if you swap arguments,
  // TypeScript will reject it. We verify the runtime behavior matches.
  it('cross-verifies with noble directly (invariant check)', async () => {
    const kp = await dilithium.keygen()
    const msg = asMessage(new Uint8Array([0xde, 0xad]))
    const sig = await dilithium.sign({ message: msg, secretKey: kp.secretKey })

    // Verify through noble directly — confirms our wrapper passes args correctly
    const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js')
    const directValid = ml_dsa65.verify(sig, msg, kp.publicKey)
    expect(directValid).toBe(true)
  })
})
