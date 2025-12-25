/**
 * Golden Test Vector Generator
 *
 * RUN ONCE to generate test vectors. NEVER regenerate unless
 * bumping format version. These vectors are the source of truth
 * for cross-package and cross-platform verification.
 *
 * Usage: npx tsx tests/golden/generate-vectors.ts
 */

import { writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// Import from built dist to ensure we test the actual package
import {
  // Identity
  generateHybridIdentity,
  getPublicKeys,
  getSecretKeys,

  // Envelope
  hybridEncrypt,
  hybridDecrypt,
  hybridDecryptToString,

  // Vault
  createEmptyVault,
  createIdentity,
  addIdentity,
  encryptVault,
  decryptVault,

  // Utils
  computeKeyFingerprint,
  computeIntegrityHash,
  sha256String,
  toHex,

  // Version
  ENVELOPE_VERSION,
  VAULT_VERSION,
  VAULT_ENCRYPTED_VERSION,
} from '../../dist/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ═══════════════════════════════════════════════════════════════════════════
// DETERMINISTIC SEED VALUES
// ═══════════════════════════════════════════════════════════════════════════

// These are NOT cryptographic keys - they're just seeds for test generation.
// Real keys are generated randomly, but we capture them for reproducibility.

const TEST_PASSWORD = 'omnituum-golden-test-2025';
const TEST_PLAINTEXT = 'Hello, Quantum World! 🔐';
const TEST_IDENTITY_NAME = 'Golden Test Identity';

// ═══════════════════════════════════════════════════════════════════════════
// GENERATE IDENTITY VECTOR
// ═══════════════════════════════════════════════════════════════════════════

async function generateIdentityVector() {
  console.log('Generating identity vector...');

  const identity = await generateHybridIdentity(TEST_IDENTITY_NAME);
  if (!identity) {
    throw new Error('Failed to generate identity');
  }

  const publicKeys = getPublicKeys(identity);
  const secretKeys = getSecretKeys(identity);
  const fingerprint = await computeKeyFingerprint(identity as any);

  // Compute expected hashes for verification
  const x25519PubHash = toHex(sha256String(identity.x25519PubHex));
  const kyberPubHash = toHex(sha256String(identity.kyberPubB64));

  const vector = {
    _comment: 'FROZEN - DO NOT REGENERATE unless bumping version',
    _generated: new Date().toISOString(),
    _version: '1.0.0',

    identity: {
      id: identity.id,
      name: identity.name,
      createdAt: identity.createdAt,
      rotationCount: identity.rotationCount,
    },

    keys: {
      x25519: {
        public: identity.x25519PubHex,
        secret: identity.x25519SecHex,
        publicHash: x25519PubHash,
      },
      kyber: {
        public: identity.kyberPubB64,
        secret: identity.kyberSecB64,
        publicHash: kyberPubHash,
        publicLength: identity.kyberPubB64.length,
        secretLength: identity.kyberSecB64.length,
      },
    },

    derived: {
      fingerprint,
      publicKeysOnly: publicKeys,
    },

    validation: {
      x25519PubLength: identity.x25519PubHex.length,
      x25519SecLength: identity.x25519SecHex.length,
      hasX25519Prefix: identity.x25519PubHex.startsWith('0x'),
    },
  };

  return { vector, identity };
}

// ═══════════════════════════════════════════════════════════════════════════
// GENERATE ENVELOPE VECTOR
// ═══════════════════════════════════════════════════════════════════════════

async function generateEnvelopeVector(senderIdentity: any, recipientIdentity: any) {
  console.log('Generating envelope vector...');

  const recipientPublicKeys = getPublicKeys(recipientIdentity);
  const recipientSecretKeys = getSecretKeys(recipientIdentity);

  // Encrypt
  const envelope = await hybridEncrypt(
    TEST_PLAINTEXT,
    recipientPublicKeys,
    { name: senderIdentity.name, id: senderIdentity.id }
  );

  // Decrypt and verify round-trip
  const decrypted = await hybridDecryptToString(envelope, recipientSecretKeys);
  if (decrypted !== TEST_PLAINTEXT) {
    throw new Error('Round-trip decryption failed!');
  }

  // Compute envelope hash for integrity
  const envelopeJson = JSON.stringify(envelope);
  const envelopeHash = toHex(sha256String(envelopeJson));

  const vector = {
    _comment: 'FROZEN - DO NOT REGENERATE unless bumping version',
    _generated: new Date().toISOString(),
    _version: '1.0.0',

    plaintext: TEST_PLAINTEXT,
    plaintextHex: toHex(new TextEncoder().encode(TEST_PLAINTEXT)),

    envelope: {
      v: envelope.v,
      suite: envelope.suite,
      aead: envelope.aead,
      x25519Epk: envelope.x25519Epk,
      x25519Wrap: envelope.x25519Wrap,
      kyberKemCt: envelope.kyberKemCt,
      kyberWrap: envelope.kyberWrap,
      contentNonce: envelope.contentNonce,
      ciphertext: envelope.ciphertext,
      meta: envelope.meta,
    },

    recipient: {
      x25519PubHex: recipientIdentity.x25519PubHex,
      x25519SecHex: recipientIdentity.x25519SecHex,
      kyberPubB64: recipientIdentity.kyberPubB64,
      kyberSecB64: recipientIdentity.kyberSecB64,
    },

    validation: {
      envelopeHash,
      expectedVersion: ENVELOPE_VERSION,
      decryptedMatches: true,
    },
  };

  return { vector, envelope };
}

// ═══════════════════════════════════════════════════════════════════════════
// GENERATE VAULT VECTOR
// ═══════════════════════════════════════════════════════════════════════════

async function generateVaultVector(identity: any) {
  console.log('Generating vault vector...');

  // Create vault and add identity
  let vault = createEmptyVault();
  vault = addIdentity(vault, identity);

  // Compute integrity hash
  const expectedIntegrityHash = computeIntegrityHash(vault.identities);

  // Encrypt vault
  const encryptedVault = await encryptVault(vault, TEST_PASSWORD);

  // Decrypt and verify round-trip
  const decryptedVault = await decryptVault(encryptedVault, TEST_PASSWORD);
  if (decryptedVault.identities.length !== 1) {
    throw new Error('Vault round-trip failed!');
  }
  if (decryptedVault.identities[0].id !== identity.id) {
    throw new Error('Identity mismatch after vault round-trip!');
  }

  const vector = {
    _comment: 'FROZEN - DO NOT REGENERATE unless bumping version',
    _generated: new Date().toISOString(),
    _version: '1.0.0',

    password: TEST_PASSWORD,

    decryptedVault: {
      version: vault.version,
      identities: vault.identities.map(i => ({
        id: i.id,
        name: i.name,
        x25519PubHex: i.x25519PubHex,
        kyberPubB64: i.kyberPubB64,
        createdAt: i.createdAt,
        rotationCount: i.rotationCount,
      })),
      settings: vault.settings,
      integrityHash: vault.integrityHash,
      createdAt: vault.createdAt,
      modifiedAt: vault.modifiedAt,
    },

    encryptedVault: {
      version: encryptedVault.version,
      kdf: encryptedVault.kdf,
      iterations: encryptedVault.iterations,
      salt: encryptedVault.salt,
      iv: encryptedVault.iv,
      ciphertext: encryptedVault.ciphertext,
      algorithm: encryptedVault.algorithm,
    },

    validation: {
      expectedVaultVersion: VAULT_VERSION,
      expectedEncryptedVersion: VAULT_ENCRYPTED_VERSION,
      integrityHashMatches: vault.integrityHash === expectedIntegrityHash,
      identityCount: 1,
      roundTripSuccess: true,
    },

    // Include full identity for decryption verification
    fullIdentity: identity,
  };

  return { vector };
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════════════════════

async function main() {
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('  GOLDEN TEST VECTOR GENERATOR');
  console.log('  WARNING: Only run this once per version!');
  console.log('═══════════════════════════════════════════════════════════════\n');

  // Generate identity (will be used as both sender and recipient for envelope)
  const { vector: identityVector, identity } = await generateIdentityVector();

  // Generate a second identity for envelope recipient
  const recipient = await generateHybridIdentity('Golden Recipient');
  if (!recipient) throw new Error('Failed to generate recipient');

  // Generate envelope using first identity as sender, second as recipient
  const { vector: envelopeVector } = await generateEnvelopeVector(identity, recipient);

  // Generate vault containing the first identity
  const { vector: vaultVector } = await generateVaultVector(identity);

  // Write vectors
  const outputDir = __dirname;

  writeFileSync(
    join(outputDir, 'identity.json'),
    JSON.stringify(identityVector, null, 2)
  );
  console.log('✓ Written: identity.json');

  writeFileSync(
    join(outputDir, 'envelope.json'),
    JSON.stringify(envelopeVector, null, 2)
  );
  console.log('✓ Written: envelope.json');

  writeFileSync(
    join(outputDir, 'vault.json'),
    JSON.stringify(vaultVector, null, 2)
  );
  console.log('✓ Written: vault.json');

  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('  DONE - Vectors are now FROZEN');
  console.log('  Run tests/golden/verify-vectors.ts to validate');
  console.log('═══════════════════════════════════════════════════════════════');
}

main().catch(e => {
  console.error('FATAL:', e);
  process.exit(1);
});
