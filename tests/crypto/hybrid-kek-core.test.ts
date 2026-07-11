/**
 * CM-25 / F11 KAT gate — byte-identity proof that the private KEK core
 * introduced by the combiner-export refactor reproduces the exact bytes
 * the pre-refactor, module-private `combinedKekV2` produced.
 *
 * This is an internal white-box test: `deriveCombinedKek` is exported at
 * the file level ONLY so this test can reach it — it is intentionally NOT
 * part of the public npm surface (see SPEC_CM25_F11_COMBINER_EXPORT.md §0/§4:
 * "MUST stay module-private"). The package's package.json `exports` map only
 * exposes barrel paths (`./`, `./crypto`, `./vault`, `./utils`, each
 * resolving to that subpath's index bundle), never the hybrid module
 * directly — and neither `src/crypto/index.ts` nor `src/index.ts`
 * re-export this symbol. No external consumer can reach it through any
 * resolvable import path.
 *
 * Golden value provenance: captured 2026-07-11 from the ACTUAL pre-refactor
 * `combinedKekV2` (via a temporary same-file export, exercised, then
 * reverted — see the CM-25/F11 implementation session) for the fixed KAT
 * tuple below. This is not a fabricated expectation; it is what the shipped
 * 0.6.0 code produced for these exact inputs before this refactor touched
 * anything.
 */

import { describe, it, expect } from 'vitest';
import { deriveCombinedKek } from '../../src/crypto/hybrid';

describe('CM-25/F11 KAT gate: deriveCombinedKek reproduces pre-refactor combinedKekV2', () => {
  it('matches the golden KEK captured from the pre-refactor implementation', () => {
    const ss_mlkem = new Uint8Array(32).map((_, i) => (i * 11 + 3) & 0xff);
    const ss_x25519 = new Uint8Array(32).map((_, i) => (i * 13 + 5) & 0xff);
    const epk = 'a1b2c3d4e5f6' + '00'.repeat(26); // fixed fake hex epk (38 bytes hex-encoded)
    const kemCtBytes = new Uint8Array(1568).map((_, i) => (i * 7 + 9) & 0xff);
    const kemCt = Buffer.from(kemCtBytes).toString('base64');

    const salt = new TextEncoder().encode('omnituum/hybrid-v2');
    const info = new TextEncoder().encode(`wrap-ck|${epk}|${kemCt}`);

    const kek = deriveCombinedKek(ss_mlkem, ss_x25519, salt, info);

    // GOLDEN VALUE — captured from the real pre-refactor combinedKekV2,
    // 2026-07-11. Do NOT update this to match new output; if this fails,
    // the refactor broke byte-identity with the frozen omnituum.hybrid.v2
    // wire (CSH-10 canary) — STOP and report the divergence.
    expect(Buffer.from(kek).toString('hex')).toBe(
      '2b7088c9ea666ff821ae5e281d09cb10d7808ff6774374e23f609ee35f81a5c1'
    );
  });
});
