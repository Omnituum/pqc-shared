/**
 * Omnituum PQC Shared - Vault Manager
 *
 * High-level operations for managing the PQC identity vault.
 * Handles identity creation, rotation, import/export, and session management.
 */

import type {
  OmnituumVault,
  HybridIdentityRecord,
  VaultSettings,
  VaultSession,
} from './types';
import { encryptVaultToBlob } from './encrypt';
import { decryptVaultFromFile } from './decrypt';
import { computeIntegrityHash } from '../utils/integrity';
import { generateId } from '../utils/entropy';
import { generateX25519Keypair, generateKyberKeypair, toHex } from '../crypto';
import { VAULT_VERSION } from '../version';

// ═══════════════════════════════════════════════════════════════════════════
// VAULT CREATION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Create a new empty vault.
 */
export function createEmptyVault(): OmnituumVault {
  const now = new Date().toISOString();
  return {
    version: VAULT_VERSION,
    identities: [],
    settings: {
      autoUnlock: false,
      lockTimeout: 15,
      showFingerprints: true,
    },
    integrityHash: computeIntegrityHash([]),
    createdAt: now,
    modifiedAt: now,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// IDENTITY MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Create a new hybrid identity.
 */
export async function createIdentity(name: string): Promise<HybridIdentityRecord | null> {
  // Generate X25519 keypair
  const x25519 = generateX25519Keypair();

  // Generate Kyber keypair
  const kyber = await generateKyberKeypair();
  if (!kyber) {
    console.error('Kyber key generation failed');
    return null;
  }

  const now = new Date().toISOString();
  const deviceFingerprint = await getDeviceFingerprint();

  return {
    id: generateId(),
    name,
    x25519PubHex: x25519.publicHex,
    x25519SecHex: x25519.secretHex,
    kyberPubB64: kyber.publicB64,
    kyberSecB64: kyber.secretB64,
    createdAt: now,
    rotationCount: 0,
    deviceFingerprint,
  };
}

/**
 * Add an identity to the vault.
 */
export function addIdentity(vault: OmnituumVault, identity: HybridIdentityRecord): OmnituumVault {
  const identities = [...vault.identities, identity];
  return {
    ...vault,
    identities,
    integrityHash: computeIntegrityHash(identities),
    modifiedAt: new Date().toISOString(),
  };
}

/**
 * Remove an identity from the vault.
 */
export function removeIdentity(vault: OmnituumVault, identityId: string): OmnituumVault {
  const identities = vault.identities.filter(i => i.id !== identityId);
  return {
    ...vault,
    identities,
    integrityHash: computeIntegrityHash(identities),
    modifiedAt: new Date().toISOString(),
    settings: {
      ...vault.settings,
      lastUsedIdentity: vault.settings.lastUsedIdentity === identityId
        ? undefined
        : vault.settings.lastUsedIdentity,
    },
  };
}

/**
 * Rotate keys for an identity (regenerate Kyber + X25519).
 */
export async function rotateIdentityKeys(
  vault: OmnituumVault,
  identityId: string
): Promise<OmnituumVault | null> {
  const index = vault.identities.findIndex(i => i.id === identityId);
  if (index === -1) return null;

  const existing = vault.identities[index];

  // Generate new X25519 keypair
  const x25519 = generateX25519Keypair();

  // Generate new Kyber keypair
  const kyber = await generateKyberKeypair();
  if (!kyber) return null;

  const now = new Date().toISOString();

  const updated: HybridIdentityRecord = {
    ...existing,
    x25519PubHex: x25519.publicHex,
    x25519SecHex: x25519.secretHex,
    kyberPubB64: kyber.publicB64,
    kyberSecB64: kyber.secretB64,
    lastRotatedAt: now,
    rotationCount: existing.rotationCount + 1,
  };

  const identities = [...vault.identities];
  identities[index] = updated;

  return {
    ...vault,
    identities,
    integrityHash: computeIntegrityHash(identities),
    modifiedAt: now,
  };
}

/**
 * Update identity metadata.
 */
export function updateIdentityMetadata(
  vault: OmnituumVault,
  identityId: string,
  updates: Partial<Pick<HybridIdentityRecord, 'name' | 'metadata'>>
): OmnituumVault {
  const identities = vault.identities.map(i =>
    i.id === identityId ? { ...i, ...updates } : i
  );
  return {
    ...vault,
    identities,
    integrityHash: computeIntegrityHash(identities),
    modifiedAt: new Date().toISOString(),
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// VAULT SETTINGS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Update vault settings.
 */
export function updateSettings(
  vault: OmnituumVault,
  settings: Partial<VaultSettings>
): OmnituumVault {
  return {
    ...vault,
    settings: { ...vault.settings, ...settings },
    modifiedAt: new Date().toISOString(),
  };
}

/**
 * Set the active identity.
 */
export function setActiveIdentity(vault: OmnituumVault, identityId: string): OmnituumVault {
  return updateSettings(vault, { lastUsedIdentity: identityId });
}

// ═══════════════════════════════════════════════════════════════════════════
// IMPORT / EXPORT
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Export vault to encrypted file.
 */
export async function exportVault(vault: OmnituumVault, password: string): Promise<Blob> {
  return encryptVaultToBlob(vault, password);
}

/**
 * Import vault from encrypted file.
 */
export async function importVault(file: File, password: string): Promise<OmnituumVault> {
  return decryptVaultFromFile(file, password);
}

/**
 * Trigger download of encrypted vault.
 */
export async function downloadVault(vault: OmnituumVault, password: string): Promise<void> {
  const blob = await exportVault(vault, password);
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `omnituum_vault_${new Date().toISOString().split('T')[0]}.enc`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ═══════════════════════════════════════════════════════════════════════════
// SESSION MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════

let currentSession: VaultSession = {
  unlocked: false,
  sessionKey: null,
  unlockedAt: null,
  activeIdentityId: null,
};

/**
 * Get current session state.
 */
export function getSession(): VaultSession {
  return { ...currentSession };
}

/**
 * Unlock vault and store session key in memory.
 */
export async function unlockSession(password: string, vault: OmnituumVault): Promise<boolean> {
  try {
    // Verify password by attempting to encrypt/decrypt
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const passwordKey = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(password),
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );

    const sessionKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt,
        iterations: 100000, // Faster for session key
        hash: 'SHA-256',
      },
      passwordKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );

    currentSession = {
      unlocked: true,
      sessionKey,
      unlockedAt: Date.now(),
      activeIdentityId: vault.settings.lastUsedIdentity || vault.identities[0]?.id || null,
    };

    return true;
  } catch {
    return false;
  }
}

/**
 * Lock the session.
 */
export function lockSession(): void {
  currentSession = {
    unlocked: false,
    sessionKey: null,
    unlockedAt: null,
    activeIdentityId: null,
  };
}

/**
 * Set active identity in session.
 */
export function setSessionActiveIdentity(identityId: string): void {
  if (currentSession.unlocked) {
    currentSession.activeIdentityId = identityId;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// DEVICE FINGERPRINT
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Generate a device fingerprint for identity tracking.
 */
async function getDeviceFingerprint(): Promise<string> {
  const data = [
    navigator.userAgent,
    navigator.language,
    screen.width,
    screen.height,
    new Date().getTimezoneOffset(),
  ].join('|');

  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(data));
  return toHex(new Uint8Array(hash)).slice(0, 16);
}
