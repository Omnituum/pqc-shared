/**
 * Golden Test Vector Verification
 *
 * This is your PRE-AUDIT ARTIFACT. Run this before any release.
 * All assertions must pass for the crypto to be considered valid.
 *
 * Usage: npx tsx tests/golden/verify-vectors.ts
 */

import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// Import from built dist to ensure we test the actual package
import {
  // Envelope
  hybridDecrypt,
  hybridDecryptToString,

  // Vault
  decryptVault,
  encryptVault,

  // Utils
  computeKeyFingerprint,
  computeIntegrityHash,
  sha256String,
  toHex,
  fromHex,

  // Validation
  validateEnvelope,
  validateVault,
  validateEncryptedVault,

  // Version
  ENVELOPE_VERSION,
  VAULT_VERSION,
  VAULT_ENCRYPTED_VERSION,
  ENVELOPE_SUITE,
  ENVELOPE_AEAD,
  VAULT_KDF,
  VAULT_ALGORITHM,
} from '../../dist/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ═══════════════════════════════════════════════════════════════════════════
// TEST UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

let passed = 0;
let failed = 0;

function assert(condition: boolean, message: string): void {
  if (condition) {
    console.log(`  ✓ ${message}`);
    passed++;
  } else {
    console.error(`  ✗ ${message}`);
    failed++;
  }
}

function assertEqual(actual: any, expected: any, message: string): void {
  const match = JSON.stringify(actual) === JSON.stringify(expected);
  if (match) {
    console.log(`  ✓ ${message}`);
    passed++;
  } else {
    console.error(`  ✗ ${message}`);
    console.error(`    Expected: ${JSON.stringify(expected)}`);
    console.error(`    Actual:   ${JSON.stringify(actual)}`);
    failed++;
  }
}

function loadVector(name: string): any {
  const path = join(__dirname, `${name}.json`);
  return JSON.parse(readFileSync(path, 'utf-8'));
}

// ═══════════════════════════════════════════════════════════════════════════
// IDENTITY VERIFICATION
// ═══════════════════════════════════════════════════════════════════════════

async function verifyIdentity() {
  console.log('\n[IDENTITY VERIFICATION]');

  const vector = loadVector('identity');

  // Key format validation
  assert(
    vector.keys.x25519.public.startsWith('0x'),
    'X25519 public key has 0x prefix'
  );
  assertEqual(
    vector.keys.x25519.public.length,
    66,
    'X25519 public key length is 66 (0x + 64 hex)'
  );
  assertEqual(
    vector.keys.x25519.secret.length,
    66,
    'X25519 secret key length is 66 (0x + 64 hex)'
  );

  // Kyber key size validation
  // kyber-crystals uses Kyber-1024 by default:
  // - Public key: ~1568 bytes = ~2092 chars base64
  // - Secret key: ~3168 bytes = ~4224 chars base64
  assert(
    vector.keys.kyber.publicLength >= 2000 && vector.keys.kyber.publicLength <= 2200,
    `Kyber public key length in valid range (${vector.keys.kyber.publicLength})`
  );
  assert(
    vector.keys.kyber.secretLength >= 4100 && vector.keys.kyber.secretLength <= 4400,
    `Kyber secret key length in valid range (${vector.keys.kyber.secretLength})`
  );

  // Hash verification
  const computedX25519Hash = toHex(sha256String(vector.keys.x25519.public));
  assertEqual(
    computedX25519Hash,
    vector.keys.x25519.publicHash,
    'X25519 public key hash matches stored hash'
  );

  const computedKyberHash = toHex(sha256String(vector.keys.kyber.public));
  assertEqual(
    computedKyberHash,
    vector.keys.kyber.publicHash,
    'Kyber public key hash matches stored hash'
  );

  // Fingerprint verification
  const identity = {
    x25519PubHex: vector.keys.x25519.public,
    kyberPubB64: vector.keys.kyber.public,
  };
  const computedFingerprint = await computeKeyFingerprint(identity as any);
  assertEqual(
    computedFingerprint,
    vector.derived.fingerprint,
    'Computed fingerprint matches stored fingerprint'
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// ENVELOPE VERIFICATION
// ═══════════════════════════════════════════════════════════════════════════

async function verifyEnvelope() {
  console.log('\n[ENVELOPE VERIFICATION]');

  const vector = loadVector('envelope');

  // Version validation
  assertEqual(
    vector.envelope.v,
    ENVELOPE_VERSION,
    `Envelope version is ${ENVELOPE_VERSION}`
  );
  assertEqual(
    vector.envelope.suite,
    ENVELOPE_SUITE,
    `Envelope suite is ${ENVELOPE_SUITE}`
  );
  assertEqual(
    vector.envelope.aead,
    ENVELOPE_AEAD,
    `Envelope AEAD is ${ENVELOPE_AEAD}`
  );

  // Structure validation
  const validation = validateEnvelope(vector.envelope);
  assert(
    validation.valid,
    `Envelope structure is valid (${validation.errors.join(', ') || 'no errors'})`
  );

  // Hash verification
  const envelopeJson = JSON.stringify(vector.envelope);
  const computedHash = toHex(sha256String(envelopeJson));
  assertEqual(
    computedHash,
    vector.validation.envelopeHash,
    'Envelope hash matches stored hash'
  );

  // Decryption verification
  const secretKeys = {
    x25519SecHex: vector.recipient.x25519SecHex,
    kyberSecB64: vector.recipient.kyberSecB64,
  };

  try {
    const decrypted = await hybridDecryptToString(vector.envelope, secretKeys);
    assertEqual(
      decrypted,
      vector.plaintext,
      'Decrypted plaintext matches original'
    );
  } catch (e) {
    console.error(`  ✗ Decryption failed: ${e}`);
    failed++;
  }

  // Plaintext hex verification
  const plaintextBytes = new TextEncoder().encode(vector.plaintext);
  const computedPlaintextHex = toHex(plaintextBytes);
  assertEqual(
    computedPlaintextHex,
    vector.plaintextHex,
    'Plaintext hex encoding matches'
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// VAULT VERIFICATION
// ═══════════════════════════════════════════════════════════════════════════

async function verifyVault() {
  console.log('\n[VAULT VERIFICATION]');

  const vector = loadVector('vault');

  // Version validation
  assertEqual(
    vector.decryptedVault.version,
    VAULT_VERSION,
    `Vault version is ${VAULT_VERSION}`
  );
  assertEqual(
    vector.encryptedVault.version,
    VAULT_ENCRYPTED_VERSION,
    `Encrypted vault version is ${VAULT_ENCRYPTED_VERSION}`
  );
  assertEqual(
    vector.encryptedVault.kdf,
    VAULT_KDF,
    `KDF is ${VAULT_KDF}`
  );
  assertEqual(
    vector.encryptedVault.algorithm,
    VAULT_ALGORITHM,
    `Algorithm is ${VAULT_ALGORITHM}`
  );

  // Structure validation
  const encValidation = validateEncryptedVault(vector.encryptedVault);
  assert(
    encValidation.valid,
    `Encrypted vault structure is valid (${encValidation.errors.join(', ') || 'no errors'})`
  );

  // Integrity hash verification
  const identitiesForHash = vector.decryptedVault.identities.map((i: any) => ({
    id: i.id,
    name: i.name,
    x25519PubHex: i.x25519PubHex,
    kyberPubB64: i.kyberPubB64,
    createdAt: i.createdAt,
    rotationCount: i.rotationCount,
  }));
  const computedIntegrity = computeIntegrityHash(identitiesForHash);
  assertEqual(
    computedIntegrity,
    vector.decryptedVault.integrityHash,
    'Computed integrity hash matches stored hash'
  );

  // Decryption verification
  try {
    const decrypted = await decryptVault(vector.encryptedVault, vector.password);

    assertEqual(
      decrypted.version,
      vector.decryptedVault.version,
      'Decrypted vault version matches'
    );
    assertEqual(
      decrypted.identities.length,
      vector.decryptedVault.identities.length,
      'Decrypted vault identity count matches'
    );
    assertEqual(
      decrypted.identities[0].id,
      vector.decryptedVault.identities[0].id,
      'Decrypted vault identity ID matches'
    );
    assertEqual(
      decrypted.integrityHash,
      vector.decryptedVault.integrityHash,
      'Decrypted vault integrity hash matches'
    );
  } catch (e) {
    console.error(`  ✗ Vault decryption failed: ${e}`);
    failed++;
  }

  // Re-encryption round-trip (different salt/IV each time, but should decrypt)
  try {
    const fullIdentity = vector.fullIdentity;
    const vault = {
      version: VAULT_VERSION as const,
      identities: [fullIdentity],
      settings: vector.decryptedVault.settings,
      integrityHash: vector.decryptedVault.integrityHash,
      createdAt: vector.decryptedVault.createdAt,
      modifiedAt: vector.decryptedVault.modifiedAt,
    };

    const reEncrypted = await encryptVault(vault, vector.password);
    const reDecrypted = await decryptVault(reEncrypted, vector.password);

    assertEqual(
      reDecrypted.identities[0].id,
      fullIdentity.id,
      'Re-encrypted vault round-trip preserves identity'
    );
  } catch (e) {
    console.error(`  ✗ Re-encryption round-trip failed: ${e}`);
    failed++;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// CROSS-PACKAGE PARITY
// ═══════════════════════════════════════════════════════════════════════════

async function verifyCrossPackageParity() {
  console.log('\n[CROSS-PACKAGE PARITY]');

  // Verify that version constants are consistent
  assertEqual(
    ENVELOPE_VERSION,
    'omnituum.hybrid.v1',
    'ENVELOPE_VERSION constant is correct'
  );
  assertEqual(
    VAULT_VERSION,
    'omnituum.vault.v1',
    'VAULT_VERSION constant is correct'
  );
  assertEqual(
    VAULT_ENCRYPTED_VERSION,
    'omnituum.vault.enc.v1',
    'VAULT_ENCRYPTED_VERSION constant is correct'
  );
  assertEqual(
    ENVELOPE_SUITE,
    'x25519+kyber768',
    'ENVELOPE_SUITE constant is correct'
  );
  assertEqual(
    ENVELOPE_AEAD,
    'xsalsa20poly1305',
    'ENVELOPE_AEAD constant is correct'
  );
  assertEqual(
    VAULT_KDF,
    'PBKDF2-SHA256',
    'VAULT_KDF constant is correct'
  );
  assertEqual(
    VAULT_ALGORITHM,
    'AES-256-GCM',
    'VAULT_ALGORITHM constant is correct'
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════════════════════

async function main() {
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('  GOLDEN TEST VECTOR VERIFICATION');
  console.log('  PRE-AUDIT ARTIFACT - All tests must pass');
  console.log('═══════════════════════════════════════════════════════════════');

  await verifyIdentity();
  await verifyEnvelope();
  await verifyVault();
  await verifyCrossPackageParity();

  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log(`  RESULTS: ${passed} passed, ${failed} failed`);
  console.log('═══════════════════════════════════════════════════════════════');

  if (failed > 0) {
    console.error('\n⚠️  VERIFICATION FAILED - DO NOT SHIP');
    process.exit(1);
  } else {
    console.log('\n✓ ALL TESTS PASSED - Ready for audit');
    process.exit(0);
  }
}

main().catch(e => {
  console.error('FATAL:', e);
  process.exit(1);
});
