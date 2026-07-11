# pqc-shared — CM-25 / F11 Hybrid Combiner Export — Normative Spec

**Status:** **FROZEN FOR IMPLEMENTATION 2026-07-11** (design-owner §9 sign-off applied; encoding vectors V-RID-1/V-TX-1/V-TX-2 frozen with real bytes, §10). Additive minor. Spec/design only — no `src/` code written, nothing published. Implementation is the Sonnet tranche (§10.6); it MUST NOT alter any frozen signature, byte grammar, or vector without re-opening design.
**Date:** 2026-07-11
**Authoring note:** the intended owner is the `pqc-shared-spec-writer` agent, which is **not configured in this environment**; authored inline as an Opus design pass. Flag for the design owner: if a dedicated Spec GPT exists (per `PQC_SHARED_GPT_INSTRUCTIONS`), reconcile this draft with it before the first implementation commit.
**Upstream authority:** ratified CM-25 design record, tracked at `sdk/loggie-sdk/packages/core/package-docs/specs/SPEC_CM_25.md` (promoted 2026-07-11 from a `package-docs/scratch/` working draft; content preserved verbatim including its Appendix A pressure-test review), §5 / Appendix A.2 (frozen contract), A.3/A.4/A.8/A.9.
**Governs:** new public exports in `@omnituum/pqc-shared` + internal refactor of `src/crypto/hybrid.ts` onto a private KEK core. Coordinated with **F11** (X25519 public-from-secret + raw keypair helpers). Registry state: npm `dist-tags.latest = 0.6.0`; this ships as the next additive minor on top.
**Promotion note (2026-07-11):** this file was promoted from a gitignored `package-docs/scratch/` draft to the pqc-shared repo root so it is tracked in git — `package-docs/` remains fully gitignored per the workspace's repository-wide containment policy for this repo; only this one ratified artifact (and the loggie-sdk design record it depends on) were moved to tracked locations. No other containment-policy change was made.

---

## 0. Normative scope & invariants

- **MUST** expose exactly four new public symbols + their types (§1). `combinedKekV2` and all KEK/shared-secret material **MUST** stay module-private.
- **MUST** refactor `omnituum.hybrid.v2` (`hybridEncrypt`/`hybridDecrypt`) onto a shared **private** KEK-derive core such that its on-wire bytes are **unchanged** (§5 KAT gate). This is the CSH-10 / frozen-`OmniHybridV2` canary.
- **MUST NOT** change the `omnituum.hybrid.v2` wire, suite, AEAD, salt, or transcript grammar.
- **MUST** be additive-only: no signature change to any existing export. Semver **minor** (§8).
- The public wrap primitive **MUST** take the content key and perform the authenticated wrap internally; the caller **MUST NOT** be able to obtain a KEK. Fail-closed: any failure throws, no fallback, no OR path (Appendix A.1/A.7).

RFC 2119 keywords are normative.

---

## 1. Exact TypeScript signatures (frozen)

```ts
// ── Branded domain-separation tag ────────────────────────────────────────────
/** HKDF salt / domain-separation tag, canonical form 'owner/profile'
 *  (e.g. 'omnituum/hybrid-v2', 'loggie/hybrid-v3'). Branded so it cannot be
 *  built from a raw string without passing hybridDomain()'s shape guard. */
export type HybridDomain = string & { readonly __hybridDomain: unique symbol };

/** Construct a validated HybridDomain. Throws InvalidHybridDomainError unless
 *  `namespaced` matches EXACTLY /^[a-z0-9][a-z0-9.-]*\/[a-z0-9][a-z0-9.-]*$/
 *  (exactly one slash; each side lowercase ASCII [a-z0-9], '.', '-', starting
 *  alphanumeric, non-empty). Rejects non-canonical input — does NOT lowercase
 *  or normalize (design-owner sign-off §9.4). Same grammar both sides. */
export function hybridDomain(namespaced: string): HybridDomain;

// ── Stable recipient identity ────────────────────────────────────────────────
export interface HybridRecipientPub { x25519PubHex: string; kyberPubB64: string; }
export interface HybridRecipientSec { x25519SecHex: string; kyberSecB64: string; }

/** Canonical, stable recipient identifier — 32 bytes, SHA-256 over a
 *  length-framed, domain-separated encoding of the recipient's public key
 *  material (§2). Exported so every consumer (loggie, pqc-db) derives the SAME
 *  id; MUST NOT be re-implemented downstream. Throws on malformed key material
 *  (wrong X25519 length, wrong ML-KEM-1024 public-key length). */
export function hybridRecipientId(pub: HybridRecipientPub): Uint8Array;

// ── Structured wrap context ──────────────────────────────────────────────────
export interface HybridWrapContext {
  /** MANDATORY. HKDF salt / domain separation. secretbox has no AAD channel,
   *  so this is a primary binding surface. */
  domain: HybridDomain;
  /** MANDATORY. Stable recipient id (typically hybridRecipientId(pub), or a
   *  frozen identity CID that provably commits to the same key material).
   *  Bound into the KEK transcript. MUST NOT be an array index. */
  recipientId: Uint8Array;
  /** OPTIONAL. Outer-protocol PRE-WRAP transcript bytes (e.g. thread id ||
   *  sender CID || content hash). MUST NOT be the post-wrap envelope/signature
   *  hash — see §3 circularity caveat. Bound as sha256(aad) into the info. */
  aad?: Uint8Array;
}

// ── Wire output ──────────────────────────────────────────────────────────────
export interface HybridCkWrap {
  x25519Epk: string;          // hex; ephemeral, generated INTERNALLY
  mlKemCiphertext: string;    // base64
  ckWrap: { nonce: string; wrapped: string };  // base64/base64
}

// ── The primitive ────────────────────────────────────────────────────────────
/** Wrap a caller-owned 32-byte content key for ONE recipient under an
 *  AND-combined KEK = HKDF(ss_mlkem || ss_x25519, salt=domain, info=transcript).
 *  Ephemeral X25519 keypair, both shared secrets, the KEK and all nonces are
 *  generated/derived INTERNALLY and zeroized in finally. Throws
 *  (InvalidKeyMaterialError / InvalidContentKeyError) on malformed pub material
 *  or contentKey.length !== 32. Does NOT retain or zeroize contentKey (caller
 *  owns it; loggie reuses one CK across N recipients). */
export function wrapContentKeyHybrid(
  contentKey: Uint8Array,
  recipientPub: HybridRecipientPub,
  ctx: HybridWrapContext,
): Promise<HybridCkWrap>;

/** Unwrap for ONE recipient. Requires BOTH secrets; ANY failure throws
 *  (HybridUnwrapError) — no classical fallback, no OR path, no
 *  try-one-then-the-other. `ctx` MUST carry the same domain + recipientId
 *  (+ aad) used at wrap or KEK re-derivation fails closed. Returns a fresh
 *  Uint8Array the CALLER must zeroize. */
export function unwrapContentKeyHybrid(
  wrap: HybridCkWrap,
  recipientSec: HybridRecipientSec,
  ctx: HybridWrapContext,
): Promise<Uint8Array>;
```

**Error taxonomy (normative, all extend a `HybridError` base):** `InvalidHybridDomainError`, `InvalidKeyMaterialError`, `InvalidContentKeyError`, `HybridUnwrapError`. Unwrap MUST surface a single opaque `HybridUnwrapError` for every internal failure (decapsulation, ECDH, KEK, auth) — it MUST NOT leak which stage failed (avoids an oracle distinguishing "bad ML-KEM ct" from "bad wrap").

---

## 2. `hybridRecipientId` canonical encoding (the cross-repo interop point)

This is the one value loggie **and** pqc-db must derive byte-identically; it is therefore specified exhaustively and exported (never re-implemented downstream).

**Inputs → normalized bytes:**
- `x25519PubHex`: strip a leading `0x` if present, lowercase, hex-decode → `x` (**MUST** be exactly 32 bytes, else `InvalidKeyMaterialError`).
- `kyberPubB64`: base64-decode → `k` (**MUST** be exactly `KYBER_PUBLIC_KEY_SIZE` = 1568 bytes, ML-KEM-1024 FIPS 203, else `InvalidKeyMaterialError`).

**Derivation (length-framed, domain-separated — no field-boundary ambiguity):**
```
LABEL = ascii("omnituum/hybrid-recipient-id/v1")     // 31 bytes, fixed
msg   = LABEL
      || u32be(x.length) || x                        // 4 + 32
      || u32be(k.length) || k                        // 4 + 1568
recipientId = SHA-256(msg)                           // 32 bytes
```
`u32be` = 4-byte big-endian length prefix. Order is **X25519 first, then ML-KEM** (fixed). The label is versioned (`/v1`) so a future encoding change is a new id version, never a silent reinterpretation.

**Worked byte example (structure, not full bytes):**
`x = 20202020…` (32 B), `k = ab41…` (1568 B) ⇒
`msg = 6f6d6e6974…2f7631` (LABEL, 31 B) `‖ 00000020` (u32be 32) `‖ <32 B x>` `‖ 00000620` (u32be 1568) `‖ <1568 B k>`; total `31 + 4 + 32 + 4 + 1568 = 1639` bytes; `recipientId = SHA256(msg)` (32 B). Swapping `x`/`k` order, or dropping the length frames, yields a different digest — that is the point.

**Rationale:** length framing defeats the classic `H(a‖b)` collision where a suffix of `a` merges with a prefix of `b`; the versioned label domain-separates this id from every other SHA-256 use in the suite; exporting the function is what prevents loggie and pqc-db drifting into two incompatible ids (the F10/CM-25 failure mode one layer down).

**Normative note (flag for design owner):** the ratified design (Appendix A.2) allows a caller to substitute "a frozen identity CID that provably commits to the same key material." This spec does **not** define that CID binding — it is out of pqc-shared scope. If loggie passes its identity CID as `recipientId`, loggie **MUST** guarantee that CID commits to `(x25519Pub, kyberPub)`; pqc-shared cannot verify that and treats `recipientId` as opaque bytes bound into the transcript.

---

## 3. Structured context → HKDF encoding (BINARY canonical transcript)

**Design-owner sign-off §9.2 (REVISED):** the textual `wrap-ck|epk|kemCt|rid=…|aad=…` serialization is **rejected** as the permanent transcript grammar — delimiter/string serialization is precisely what gets independently rebuilt with a casing/encoding/omitted-field ambiguity. The v3 / public-primitive profile uses a **binary, typed, length-framed transcript owned entirely by pqc-shared**. Public callers pass the structured `HybridWrapContext` and **MUST NEVER** construct HKDF `info` bytes themselves.

The private KEK core computes `KEK = hkdfSha256(ikm, { salt, info, length: 32 })` where `ikm = ss_mlkem || ss_x25519` (ML-KEM first — **unchanged**). `salt` and `info` are built by the **profile adapter**, never the caller.

### 3.1 omnituum profile (FROZEN — textual, byte-identical to today)
```
salt = utf8('omnituum/hybrid-v2')
info = utf8('wrap-ck|' + x25519EpkHex + '|' + kyberKemCtB64)   // legacy TEXT — unchanged
```
No `recipientId`, no `aad`. Reproduces `combinedKekV2` exactly (§5 KAT gate). The binary transcript below does **NOT** apply to omnituum — its frozen wire depends on this exact legacy text.

### 3.2 v3 / public-primitive profile (BINARY canonical transcript)
`info` is the concatenation of five **fixed-order, always-present** length-framed fields. Each field is `tag(1 byte) ‖ u32be(len) ‖ value`; the AAD field is always present with `len=0` when absent (no omitted-field ambiguity). Values are **raw bytes**, never their textual (hex/base64) encoding — this is the point of a binary transcript.

```
TX_LABEL = ascii('omnituum/hybrid-kek/v1')     // 22 bytes, FROZEN single constant (owned by pqc-shared)

info =
    0x00 ‖ u32be(len(TX_LABEL)) ‖ TX_LABEL                    // context label
  ‖ 0x01 ‖ u32be(32)           ‖ epkRaw                       // X25519 ephemeral pub, RAW 32 bytes (hex-decoded)
  ‖ 0x02 ‖ u32be(len(kemRaw))  ‖ kemRaw                       // ML-KEM ciphertext, RAW bytes (base64-decoded)
  ‖ 0x03 ‖ u32be(32)           ‖ recipientId                  // 32 bytes (§2)
  ‖ 0x04 ‖ u32be(len)          ‖ (sha256(aad) | «empty»)      // 32 bytes if aad present, else len=0

salt = utf8(ctx.domain)                                       // e.g. 'loggie/hybrid-v3' (HybridDomain, §1)
```

Field tags (frozen): `0x00` LABEL, `0x01` EPK, `0x02` KEM-CT, `0x03` RECIPIENT-ID, `0x04` AAD-HASH. Ordering is fixed; all five fields always present.

**Ownership rule (MUST):** the transcript encoder is a single private pqc-shared function `buildHybridTranscriptV1(epkRaw, kemRaw, recipientId, aadHash?)`. No consumer, and no other pqc-shared module, reconstructs `info` from parts. `TX_LABEL` is one frozen constant — **MUST NOT** be reassembled from separate string fragments (design-owner §9.1 rule applied to the transcript too).

### 3.3 Rules (normative)
1. `secretbox` (XSalsa20-Poly1305) has **no AAD channel**; ALL binding rides HKDF `salt`/`info`. The v3 adapter **MUST NOT** offer a path that omits `recipientId` (field `0x03`) — it is a mandatory fixed field, not optional.
2. Values bind **raw bytes** (`epkRaw` = hex-decoded 32 B; `kemRaw` = base64-decoded ct), so hex-case or base64-padding variance in the wire encoding cannot change the KEK. The wire (`HybridCkWrap`) still carries hex/base64 for transport; the transcript binds their decoded bytes.
3. `domain` **MUST** be a `HybridDomain` (from `hybridDomain()`), guaranteeing the grammar (§1) and preventing an empty/colliding salt. The domain is the HKDF **salt**, distinct from the transcript label (which is the HKDF **info** prefix) — two independent domain-separation surfaces.
4. **`aad` circularity caveat (MUST):** for `loggie.hybrid.v3` the ECDSA/Dilithium signature canonicalizes the recipient wraps; any `aad` bound here **MUST** be computable *before* the wraps exist (thread id, sender CID, content hash) — **never** the post-wrap envelope/signature hash, or derivation becomes circular. Only `sha256(aad)` (fixed 32 B), never raw `aad`, enters the transcript.

Frozen encoding vectors for §3.2 are in §10 (V-TX-1 / V-TX-2), computed with real bytes.

---

## 4. Private KEK core vs public profile-adapter ownership

```
                         ┌─────────────────────────────────────────────┐
   PRIVATE (never exported)                                             │
   deriveCombinedKek(ss_mlkem, ss_x25519, salt, info) -> KEK(32)        │  ← the ONLY KEK math
     • ikm = ss_mlkem || ss_x25519  (fixed order)                       │    (today's combinedKekV2,
     • KEK = hkdfSha256(ikm, {salt, info, length:32})                   │     parameterized by salt+info)
     • zeroize ikm in finally                                          │
   wrapCkCore(CK, ss_mlkem, ss_x25519, salt, info) -> {nonce,wrapped}   │
   unwrapCkCore({nonce,wrapped}, ss_mlkem, ss_x25519, salt, info) -> CK │
                         └───────────────┬─────────────────────────────┘
                                         │ called by exactly two adapters
                 ┌───────────────────────┴───────────────────────┐
   PRIVATE omnituum adapter                        PUBLIC v3 adapter
   (hybridEncrypt/hybridDecrypt internals)         (wrapContentKeyHybrid /
     • builds salt/info per §3 omnituum profile      unwrapContentKeyHybrid)
       (no recipientId)                              • builds salt/info per §3 v3 profile
     • assembles OmniHybridV2 wire (unchanged)       • returns HybridCkWrap pieces only
```

**Invariants:** (a) `deriveCombinedKek`/`wrapCkCore`/`unwrapCkCore` + the private transcript builder `buildHybridTranscriptV1` (§3.2) are module-private, never exported; (b) **no code outside `deriveCombinedKek` derives a hybrid KEK** — both adapters call it; (c) the omnituum adapter passes the *exact* legacy textual salt/info (§3.1) so its bytes are unchanged; (d) ephemeral X25519 keypair generation + nonce generation live in the adapters/core, never in the caller. Per §9.5 sign-off, `combinedKekV2` is **deleted** in favor of `deriveCombinedKek` — **not** retained as a lasting alias (at most a single short-lived refactor commit).

---

## 5. `omnituum.hybrid.v2` byte-identical KAT / canary gate

**Freeze condition (MUST all hold before the minor ships):**
1. For every existing `omnituum.hybrid.v2` golden vector, `hybridEncrypt` post-refactor produces **byte-identical** wire (`v`, `suite`, `aead`, `x25519Epk` given fixed ephemeral, `kyberKemCt`, `ckWrap`, `contentNonce`, `ciphertext`). Because ephemeral values are random, byte-identity is proven at the **KEK level**: assert `deriveCombinedKek(ss_k, ss_x, 'omnituum/hybrid-v2', 'wrap-ck|'+epk+'|'+kemCt)` equals the pre-refactor `combinedKekV2(ss_k, ss_x, epk, kemCt)` for a fixed KAT tuple `(ss_k, ss_x, epk, kemCt)` → then the wrap bytes are identical for a fixed nonce.
2. Add a **frozen KAT with fixed ephemeral + fixed nonce** (test-injected RNG) so the full wire is deterministic and diffed byte-for-byte pre/post refactor.
3. `hybridDecrypt` still opens all pre-refactor v2 (and legacy v1 / pqc-demo) fixtures.
4. CSH-10 signature-root canary (loggie side) is untouched because the omnituum wire is unchanged — this gate is what guarantees that.

If any omnituum KAT byte shifts, the change is **breaking**, not additive, and **MUST NOT** ship as a minor.

---

## 6. New wrap/unwrap golden vectors

Freeze, with test-injected deterministic RNG (fixed ephemeral X25519 + fixed nonce):
- **V-WRAP-1:** fixed `(x25519Pub, kyberPub, CK, domain='loggie/hybrid-v3', recipientId, ephemeral, nonce)` → fixed `HybridCkWrap`. Round-trips under the matching secrets.
- **V-RID-1:** fixed `(x25519Pub, kyberPub)` → fixed 32-byte `recipientId` (pins §2 encoding forever).
- **V-DOMAIN-1:** `hybridDomain` accept/reject table (valid `owner/profile`; reject empty, no-slash, two-slash, uppercase, leading/trailing dash).
- **Node ≡ browser parity:** every vector above **MUST** produce byte-identical output on the Node and `.browser` twins (the combiner math is runtime-independent; only RNG/import path differ).
- **aad vector:** V-WRAP-1 with a fixed `aad` → distinct fixed wire, proving `aad` binds.

---

## 7. Invariant test matrix (each a normative MUST — fail closed)

| # | Test | Required outcome |
|---|---|---|
| I-1 | Withhold ML-KEM secret (valid X25519 secret) → unwrap | throws `HybridUnwrapError` |
| I-2 | Withhold X25519 secret (valid ML-KEM secret) → unwrap | throws `HybridUnwrapError` |
| I-3 | Corrupt `mlKemCiphertext` (swap from another wrap) | throws (KEK mismatch) |
| I-4 | Corrupt `x25519Epk` (swap from another wrap) | throws (KEK mismatch) |
| I-5 | Copy a wrap between envelopes / different CK context | throws |
| I-6 | Recipient A's wrap, recipient B's secrets | throws (ss-specific) |
| I-7 | Same key material, **mismatched `recipientId`** in ctx | throws (identity bound into KEK, not just hint) |
| I-8 | Move a valid `(epk,kemCt,ckWrap)` triple to another array slot | still opens for its true recipient; forges nothing (position ≠ identity) |
| I-9 | Public API cannot double-wrap one CK under two single-primitive KEKs to reconstruct OR | N/A at primitive; enforced by §6-doctrine lint (see note) |
| I-10 | Unwrap error is opaque across all failure stages | no stage-distinguishing oracle |

**I-9 note:** the primitive itself cannot produce OR (it emits one AND-combined wrap). OR-reconstruction is only possible via the *low-level* exports (`x25519SharedSecret`, `hkdfSha256`, `secretboxRaw`, `pqcWrapFromSharedSecret`), which remain exported for single-primitive schemes. Anti-recurrence therefore rests on the CM-25 §6 lint + doctrine, **not** this primitive — restate that in the doctrine, do not claim the export alone closes it (design record Amendment 4).

---

## 8. F11 coordination & release / version

**Bundle as one additive minor** (next after 0.6.0):
1. **CM-25 combiner export** — `wrapContentKeyHybrid`, `unwrapContentKeyHybrid`, `hybridDomain`, `hybridRecipientId`, types + errors; internal private-core refactor of `hybrid.ts`; omnituum KAT gate (§5).
2. **F11 primitives** — X25519 public-from-secret (`x25519PublicFromSecret`) + raw keypair-from-secret helper, so loggie's `scripts/lint-nacl-boundary.allowlist` entries (`wraps.ts`, `envelope-v2.ts`, `keys.ts`, etc.) can later be rerouted and deleted. These are independently additive; bundling saves one publish/coordination cycle and both are "grow the pqc-shared surface so consumers stop reaching past it."

**Semver:** **minor** (e.g. `0.7.0`), additive-only. Publish/tag gate: §5 omnituum KATs unchanged + §6 new vectors frozen + §7 invariants green + Node≡browser parity. Registry note: npm `latest` is `0.6.0`; this is the next minor on top. atlas-os and other `github:#v0.6.0` pins are unaffected until they opt in.

**Ordering vs consumers:** this minor **MUST** publish before loggie `loggie.hybrid.v3` implementation or any pqc-db per-recipient hybrid use — both consume these exports. PDB-10 may proceed in parallel binding only to the *existing* `omnituum.hybrid.v2` `hybridEncrypt`/`hybridDecrypt` (already conjunctive) per the ratified §7 — it does not need this minor to start.

---

## 9. Design-owner sign-off (2026-07-11) — RESOLVED

1. **`hybridRecipientId` encoding (§2)** — **ACCEPT as specified.** Frozen versioned label + X25519-first + u32be length framing. Recipient identity is the canonical cryptographic key tuple ONLY — never loggie metadata, array position, DID formatting, address casing, or any mutable app id. The `RID_LABEL` is frozen byte-for-byte in §2/§10 and MUST NOT be reconstructed from separate string constants. Vector V-RID-1 frozen (§10).
2. **HKDF `info` grammar (§3)** — **REVISED (accepted with change).** Textual `wrap-ck|epk|kemCt|rid=…|aad=…` **rejected**. Replaced by the §3.2 **binary, typed, length-framed canonical transcript** owned entirely by pqc-shared (private `buildHybridTranscriptV1`); public callers pass structured context and never build `info`. Binds versioned label + raw epk + raw ML-KEM ct + recipientId + sha256(aad), fixed order, unambiguous tags/lengths. Vectors V-TX-1/V-TX-2 frozen (§10).
3. **Error opacity (I-10, §1)** — **ACCEPT.** One opaque public `HybridUnwrapError` across all stages. Internal tests/debug may distinguish stages; production API errors/warnings/public `cause` MUST NOT expose which component or auth stage failed. No `console.warn` of an inner stage; no stage-leaking public cause.
4. **`hybridDomain` grammar (§1)** — **ACCEPT with frozen charset.** `owner/profile`, exactly one slash, lowercase ASCII `[a-z0-9][a-z0-9.-]*` both sides. Reject non-canonical input; NO implicit `.toLowerCase()`/normalization inside the primitive — caller supplies canonical bytes or is rejected.
5. **`combinedKekV2` disposition (§4)** — **ACCEPT replacement.** Replace with the parameterized private `deriveCombinedKek`; do **not** retain `combinedKekV2` as a permanent alias (only, at most, within one short-lived refactor commit). A lasting `…V2` name would blur math-vs-wire-vs-history — the exact naming ambiguity that helped hide CM-25. The frozen omnituum adapter preserves byte-identical behavior via explicit profile params + the §5 KAT gate.

All five resolved. None alter the ratified architecture (Option B, private core, one recipient-id owner, PDB-10 GO). The encoding layer is now pinned; §10 freezes the contract.

---

## 10. FROZEN FOR IMPLEMENTATION

Contract status: **FROZEN** at the signature + encoding level (2026-07-11). Implementation is the Sonnet tranche below; it MUST NOT alter any signature, byte grammar, or frozen vector without re-opening design.

### 10.1 Final public TypeScript signatures (frozen)
As in §1, with §9 amendments applied: `wrapContentKeyHybrid`, `unwrapContentKeyHybrid`, `hybridDomain` (grammar `^[a-z0-9][a-z0-9.-]*\/[a-z0-9][a-z0-9.-]*$`, reject-not-normalize), `hybridRecipientId`; types `HybridDomain`, `HybridRecipientPub/Sec`, `HybridWrapContext { domain, recipientId, aad? }`, `HybridCkWrap`; errors `HybridError` ⊃ `InvalidHybridDomainError | InvalidKeyMaterialError | InvalidContentKeyError | HybridUnwrapError` (unwrap opaque).

### 10.2 Frozen recipient-id encoding (§2) — `RID_LABEL = "omnituum/hybrid-recipient-id/v1"` (31 B)
`recipientId = SHA256( RID_LABEL ‖ u32be(32) ‖ x25519PubRaw ‖ u32be(1568) ‖ kyberPubRaw )`.

### 10.3 Frozen transcript encoding (§3.2) — `TX_LABEL = "omnituum/hybrid-kek/v1"` (22 B)
`info = field(0x00,TX_LABEL) ‖ field(0x01,epkRaw) ‖ field(0x02,kemRaw) ‖ field(0x03,recipientId) ‖ field(0x04, sha256(aad)|«empty»)`, `field(tag,v)=tag‖u32be(len(v))‖v`.

### 10.4 Vector inventory
**Frozen now (pure encoding/hash — real bytes, algorithmically reproducible from §2/§3.2 with the deterministic filler rules below — no external script required, any implementer can recompute):**

| ID | Fixed inputs (deterministic fillers) | Frozen output |
|---|---|---|
| **V-RID-1** | `x25519PubRaw[i]=i&0xff` (32 B); `kyberPubRaw[i]=(3i+7)&0xff` (1568 B) | `ridMsg.len=1639`; **`recipientId = 8fe406405490b6c1280e7fddecb6b5f81e170496584594366feb1e95ffb60453`** |
| **V-TX-1** (no aad) | `epkRaw[i]=(5i+1)&0xff` (32 B); `kemRaw[i]=(7i+3)&0xff` (1568 B); `recipientId=`V-RID-1 | `info.len=1679`; **`sha256(info)=930e94660ef4119cad7e9b9459a92d7415c03de803f832ed77a3a23dcf3ad9c1`** |
| **V-TX-2** (with aad) | V-TX-1 inputs + `aad=ascii("thread:abc\|sender:cid123\|content-sha256:deadbeef")` | `sha256(aad)=b08d3d87679118c23038e50be0e77e445d768d6f00ef44d7bc0519e57dd73223`; `info.len=1711`; **`sha256(info)=3ea417da526106df3edbc72315c85467682d79c30d2ff574265db1cb0aaa6e51`** |

**Produced + frozen during the Sonnet KAT-gate step (require executing the crypto stack with test-injected deterministic RNG — cannot be pre-computed at design level):**
- **V-WRAP-1** — fixed `(x25519 keypair, kyber keypair, CK, domain='loggie/hybrid-v3', recipientId=V-RID-1, ephemeral, nonce)` → fixed `HybridCkWrap`; round-trips.
- **V-DOMAIN-1** — `hybridDomain` accept/reject table (accept `loggie/hybrid-v3`, `a/b`, `x.y/z-1`; reject empty, no-slash, two-slash, `A/b`, `/b`, `a/`, `a//b`).
- **V-INVARIANT I-1…I-10** — §7 matrix as MUST-fail-closed tests.
- **Node ≡ browser parity** — every wrap/id vector byte-identical across twins.

### 10.5 omnituum.hybrid.v2 KAT gate — result: **PENDING (Sonnet gate, blocking)**
Cannot be run at design level (no refactored code exists yet). It is the **blocking first gate** of the implementation tranche: after refactoring `hybridEncrypt`/`hybridDecrypt` onto `deriveCombinedKek` via the omnituum textual profile, every existing `omnituum.hybrid.v2` KAT MUST reproduce byte-identical wire (§5). If any byte shifts → breaking, not a minor. This is the CSH-10 canary.

### 10.6 Sonnet implementation tranche order
1. **KAT-gate refactor (blocking):** introduce private `deriveCombinedKek(ss_mlkem, ss_x25519, salt, info)` + private `buildHybridTranscriptV1`; route `hybridEncrypt`/`hybridDecrypt` through the omnituum textual profile adapter; **prove §5 byte-identity** (V-omnituum KATs unchanged). Delete `combinedKekV2` (no lasting alias). No new public exports yet.
2. **New primitive:** implement `wrapContentKeyHybrid`/`unwrapContentKeyHybrid` + `hybridDomain` + `hybridRecipientId` + error taxonomy on the v3 binary-transcript adapter; freeze V-WRAP-1 + V-DOMAIN-1; assert V-RID-1/V-TX-1/V-TX-2 match §10.4.
3. **Invariant + parity gates:** §7 I-1…I-10; Node≡browser parity vectors; the §6 (CM-25 design) hybrid-KEK boundary lint.
4. **F11 primitives:** `x25519PublicFromSecret` + raw keypair-from-secret; ready loggie's `lint-nacl-boundary.allowlist` entries for later removal.
5. **Publish gate:** all above green → additive **minor** (`0.7.0`); tag; then unblock loggie `loggie.hybrid.v3` (readers-first) and any pqc-db per-recipient use.

Opus reviews steps 1–3 (crypto/key-custody); Sonnet builds. **PDB-10 runs in parallel** under its existing constraint (bind only to `omnituum.hybrid.v2`; do not consume loggie's multi-recipient path / `buildWrapsForScheme`).
