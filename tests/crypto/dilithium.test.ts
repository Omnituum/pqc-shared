/**
 * Dilithium ML-DSA-65 regression tests.
 *
 * These tests verify correct argument order for @noble/post-quantum calls.
 * A previous bug passed (secretKey, message) to sign() instead of (message, secretKey),
 * and (publicKey, message, signature) to verify() instead of (signature, message, publicKey).
 *
 * Run: cd pqc-shared && npx vitest run tests/crypto/dilithium.test.ts
 */
import { describe, it, expect } from 'vitest'
import {
  generateDilithiumKeypair,
  generateDilithiumKeypairFromSeed,
  dilithiumSign,
  dilithiumSignRaw,
  dilithiumVerify,
  dilithiumVerifyRaw,
  DILITHIUM_SIGNATURE_SIZE,
  DILITHIUM_PUBLIC_KEY_SIZE,
  DILITHIUM_SECRET_KEY_SIZE,
} from '../../src/crypto/dilithium'
import { fromB64 } from '../../src/crypto/primitives'

describe('Dilithium ML-DSA-65', () => {
  it('generates keypair with correct sizes', async () => {
    const kp = await generateDilithiumKeypair()
    expect(kp).not.toBeNull()
    const pub = fromB64(kp!.publicB64)
    const sec = fromB64(kp!.secretB64)
    expect(pub.length).toBe(DILITHIUM_PUBLIC_KEY_SIZE)
    expect(sec.length).toBe(DILITHIUM_SECRET_KEY_SIZE)
  })

  it('sign → verify roundtrip (high-level, base64)', async () => {
    const kp = await generateDilithiumKeypair()
    expect(kp).not.toBeNull()

    const msg = new Uint8Array([1, 2, 3, 4])
    const sig = await dilithiumSign(msg, kp!.secretB64)

    expect(sig.algorithm).toBe('ML-DSA-65')
    expect(fromB64(sig.signature).length).toBe(DILITHIUM_SIGNATURE_SIZE)

    const valid = await dilithiumVerify(msg, sig.signature, kp!.publicB64)
    expect(valid).toBe(true)
  })

  it('sign → verify roundtrip (raw, Uint8Array)', async () => {
    const kp = await generateDilithiumKeypair()
    expect(kp).not.toBeNull()

    const sec = fromB64(kp!.secretB64)
    const pub = fromB64(kp!.publicB64)
    const msg = new Uint8Array([10, 20, 30])

    const sig = await dilithiumSignRaw(msg, sec)
    expect(sig.length).toBe(DILITHIUM_SIGNATURE_SIZE)

    const valid = await dilithiumVerifyRaw(msg, sig, pub)
    expect(valid).toBe(true)
  })

  it('verify rejects tampered message', async () => {
    const kp = await generateDilithiumKeypair()
    expect(kp).not.toBeNull()

    const msg = new Uint8Array([1, 2, 3])
    const sig = await dilithiumSign(msg, kp!.secretB64)

    const tampered = new Uint8Array([9, 9, 9])
    const valid = await dilithiumVerify(tampered, sig.signature, kp!.publicB64)
    expect(valid).toBe(false)
  })

  it('verify rejects wrong public key', async () => {
    const kp1 = await generateDilithiumKeypair()
    const kp2 = await generateDilithiumKeypair()
    expect(kp1).not.toBeNull()
    expect(kp2).not.toBeNull()

    const msg = new Uint8Array([5, 6, 7])
    const sig = await dilithiumSign(msg, kp1!.secretB64)

    const valid = await dilithiumVerify(msg, sig.signature, kp2!.publicB64)
    expect(valid).toBe(false)
  })

  it('raw verify rejects tampered message', async () => {
    const kp = await generateDilithiumKeypair()
    expect(kp).not.toBeNull()

    const sec = fromB64(kp!.secretB64)
    const pub = fromB64(kp!.publicB64)

    const msg = new Uint8Array([1, 2, 3])
    const sig = await dilithiumSignRaw(msg, sec)

    const tampered = new Uint8Array([9, 9, 9])
    const valid = await dilithiumVerifyRaw(tampered, sig, pub)
    expect(valid).toBe(false)
  })

  it('sign with string message works', async () => {
    const kp = await generateDilithiumKeypair()
    expect(kp).not.toBeNull()

    const sig = await dilithiumSign('hello dilithium', kp!.secretB64)
    const valid = await dilithiumVerify('hello dilithium', sig.signature, kp!.publicB64)
    expect(valid).toBe(true)

    const wrongMsg = await dilithiumVerify('wrong message', sig.signature, kp!.publicB64)
    expect(wrongMsg).toBe(false)
  })

  it('deterministic keygen from seed is reproducible', async () => {
    const seed = new Uint8Array(32)
    seed.fill(42)

    const kp1 = await generateDilithiumKeypairFromSeed(seed)
    const kp2 = await generateDilithiumKeypairFromSeed(seed)

    expect(kp1.publicKey).toEqual(kp2.publicKey)
    expect(kp1.secretKey).toEqual(kp2.secretKey)
  })

  // Regression: ensures noble's argument order is correct.
  // If sign/verify args are reversed, this test will fail with a size mismatch error.
  it('regression: sign produces valid signature verifiable by noble directly', async () => {
    const kp = await generateDilithiumKeypair()
    expect(kp).not.toBeNull()

    const sec = fromB64(kp!.secretB64)
    const pub = fromB64(kp!.publicB64)
    const msg = new Uint8Array([1, 2, 3])

    // Sign through pqc-shared wrapper
    const sig = await dilithiumSignRaw(msg, sec)

    // Verify directly through noble (bypassing wrapper) to confirm correctness
    const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js')
    const directValid = ml_dsa65.verify(sig, msg, pub)
    expect(directValid).toBe(true)
  })
})
