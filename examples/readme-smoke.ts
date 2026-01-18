/**
 * README Smoke Test
 *
 * Verifies that all Quick Start examples from README.md compile and run.
 * Run with: pnpm build && pnpm tsx examples/readme-smoke.ts
 */

// ============================================================================
// Quick Start: Hybrid Encryption
// ============================================================================

import {
  generateHybridIdentity,
  hybridEncrypt,
  hybridDecryptToString,
  getPublicKeys,
} from '../dist/index.js';

async function testHybridEncryption() {
  console.log('[Hybrid Encryption]');

  // Generate identity with X25519 + Kyber keypairs
  const alice = await generateHybridIdentity('Alice');
  const bob = await generateHybridIdentity('Bob');

  if (!alice || !bob) {
    throw new Error('Failed to generate identities');
  }

  // Encrypt message for Bob using his public keys
  const bobPublicKeys = getPublicKeys(bob);
  const envelope = await hybridEncrypt(
    'Hello, Bob!',
    bobPublicKeys,
    { senderName: alice.name, senderId: alice.id }
  );

  // Bob decrypts with his secret keys
  const plaintext = await hybridDecryptToString(envelope, bob);
  console.log('  Decrypted:', plaintext);

  if (plaintext !== 'Hello, Bob!') {
    throw new Error('Decryption mismatch');
  }
  console.log('  ✓ Hybrid encryption works\n');
}

// ============================================================================
// Quick Start: Digital Signatures (Dilithium)
// ============================================================================

import {
  generateDilithiumKeypair,
  dilithiumSign,
  dilithiumVerify,
} from '../dist/index.js';

async function testDilithiumSignatures() {
  console.log('[Dilithium Signatures]');

  const keypair = await generateDilithiumKeypair();

  if (!keypair) {
    throw new Error('Failed to generate Dilithium keypair');
  }

  const message = new TextEncoder().encode('Sign this message');

  const { signature } = await dilithiumSign(message, keypair.secretB64);
  const valid = await dilithiumVerify(message, signature, keypair.publicB64);
  console.log('  Valid:', valid);

  if (!valid) {
    throw new Error('Signature verification failed');
  }
  console.log('  ✓ Dilithium signatures work\n');
}

// ============================================================================
// Quick Start: Vault Management
// ============================================================================

import {
  createEmptyVault,
  addIdentity,
  encryptVault,
  decryptVault,
} from '../dist/index.js';

async function testVaultManagement() {
  console.log('[Vault Management]');

  // Create and populate vault
  let vault = createEmptyVault();
  const identity = await generateHybridIdentity('My Identity');

  if (!identity) {
    throw new Error('Failed to create identity');
  }

  vault = addIdentity(vault, identity);

  // Encrypt vault with password (uses Argon2id)
  const encrypted = await encryptVault(vault, 'my-password');

  // Decrypt vault
  const decrypted = await decryptVault(encrypted, 'my-password');

  if (!decrypted || decrypted.identities.length !== 1) {
    throw new Error('Vault decryption failed');
  }
  console.log('  Vault identities:', decrypted.identities.length);
  console.log('  ✓ Vault management works\n');
}

// ============================================================================
// Run all tests
// ============================================================================

async function main() {
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('  README SMOKE TEST');
  console.log('═══════════════════════════════════════════════════════════════\n');

  await testHybridEncryption();
  await testDilithiumSignatures();
  await testVaultManagement();
  // Note: File encryption uses browser File/Blob APIs, tested separately

  console.log('═══════════════════════════════════════════════════════════════');
  console.log('  ✓ ALL README EXAMPLES PASS');
  console.log('═══════════════════════════════════════════════════════════════');
}

main().catch((err) => {
  console.error('FATAL:', err);
  process.exit(1);
});
