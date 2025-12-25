/**
 * Omnituum PQC Shared - Security Utilities
 *
 * Memory hygiene, secure comparison, and session management utilities.
 * These are critical for enterprise credibility and threat model legitimacy.
 */

// ═══════════════════════════════════════════════════════════════════════════
// MEMORY ZEROING
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Securely zero out a Uint8Array to prevent sensitive data from lingering in memory.
 *
 * Note: JavaScript garbage collection may still leave copies. This is a best-effort
 * approach for browser environments. For maximum security, use Web Assembly or
 * native code.
 *
 * @param arr - Array to zero
 */
export function zeroMemory(arr: Uint8Array): void {
  if (!arr || arr.length === 0) return;

  // Fill with zeros
  arr.fill(0);

  // Try to prevent optimizer from removing the fill
  // This is a best-effort approach
  if (arr[0] !== 0) {
    throw new Error('Memory zeroing failed');
  }
}

/**
 * Zero multiple arrays at once.
 *
 * @param arrays - Arrays to zero
 */
export function zeroAll(...arrays: (Uint8Array | null | undefined)[]): void {
  for (const arr of arrays) {
    if (arr) {
      zeroMemory(arr);
    }
  }
}

/**
 * Execute a function and zero the result after a callback processes it.
 * Ensures sensitive data is cleared even if callback throws.
 *
 * @param getData - Function that returns sensitive data
 * @param process - Function to process the data
 * @returns Result of process function
 */
export async function withSecureData<T, R>(
  getData: () => Promise<Uint8Array>,
  process: (data: Uint8Array) => Promise<R>
): Promise<R> {
  let data: Uint8Array | null = null;
  try {
    data = await getData();
    return await process(data);
  } finally {
    if (data) {
      zeroMemory(data);
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANT-TIME COMPARISON
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Compare two byte arrays in constant time to prevent timing attacks.
 *
 * @param a - First array
 * @param b - Second array
 * @returns true if arrays are equal
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }

  return result === 0;
}

/**
 * Compare two strings in constant time.
 *
 * @param a - First string
 * @param b - Second string
 * @returns true if strings are equal
 */
export function constantTimeStringEqual(a: string, b: string): boolean {
  const encoder = new TextEncoder();
  return constantTimeEqual(encoder.encode(a), encoder.encode(b));
}

// ═══════════════════════════════════════════════════════════════════════════
// SESSION MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════

export type UnlockReason =
  | 'password'        // User entered password
  | 'biometric'       // Biometric authentication (future)
  | 'hardware_key'    // Hardware security key (future)
  | 'session_restore' // Restored from saved session
  | 'api_token'       // API token authentication
  | 'unknown';

export interface SecureSession {
  /** Session is currently unlocked */
  unlocked: boolean;

  /** Timestamp when session was unlocked (ms since epoch) */
  unlockedAt: number | null;

  /** Session timeout in milliseconds (0 = never) */
  timeoutMs: number;

  /** How the session was unlocked */
  unlockReason: UnlockReason | null;

  /** Optional session identifier */
  sessionId: string | null;

  /** Last activity timestamp (ms since epoch) */
  lastActivityAt: number | null;

  /** Number of failed unlock attempts */
  failedAttempts: number;

  /** Lockout until timestamp (ms since epoch) if too many failed attempts */
  lockedOutUntil: number | null;
}

/**
 * Create a new locked session.
 */
export function createSession(timeoutMs: number = 15 * 60 * 1000): SecureSession {
  return {
    unlocked: false,
    unlockedAt: null,
    timeoutMs,
    unlockReason: null,
    sessionId: null,
    lastActivityAt: null,
    failedAttempts: 0,
    lockedOutUntil: null,
  };
}

/**
 * Unlock a secure session.
 */
export function unlockSecureSession(
  session: SecureSession,
  reason: UnlockReason = 'password'
): SecureSession {
  const now = Date.now();
  return {
    ...session,
    unlocked: true,
    unlockedAt: now,
    unlockReason: reason,
    sessionId: generateSessionId(),
    lastActivityAt: now,
    failedAttempts: 0,
    lockedOutUntil: null,
  };
}

/**
 * Lock a secure session and clear sensitive state.
 */
export function lockSecureSession(session: SecureSession): SecureSession {
  return {
    ...session,
    unlocked: false,
    unlockedAt: null,
    unlockReason: null,
    sessionId: null,
    lastActivityAt: null,
  };
}

/**
 * Record session activity (resets timeout).
 */
export function touchSession(session: SecureSession): SecureSession {
  if (!session.unlocked) {
    return session;
  }
  return {
    ...session,
    lastActivityAt: Date.now(),
  };
}

/**
 * Check if session has timed out.
 */
export function isSessionTimedOut(session: SecureSession): boolean {
  if (!session.unlocked || session.timeoutMs === 0) {
    return false;
  }

  const lastActivity = session.lastActivityAt ?? session.unlockedAt ?? 0;
  return Date.now() - lastActivity > session.timeoutMs;
}

/**
 * Check if session should be auto-locked.
 */
export function shouldAutoLock(session: SecureSession): boolean {
  return session.unlocked && isSessionTimedOut(session);
}

/**
 * Record a failed unlock attempt.
 */
export function recordFailedAttempt(
  session: SecureSession,
  lockoutThreshold: number = 5,
  lockoutDurationMs: number = 5 * 60 * 1000
): SecureSession {
  const newAttempts = session.failedAttempts + 1;
  const isLockedOut = newAttempts >= lockoutThreshold;

  return {
    ...session,
    failedAttempts: newAttempts,
    lockedOutUntil: isLockedOut ? Date.now() + lockoutDurationMs : null,
  };
}

/**
 * Check if session is in lockout state.
 */
export function isLockedOut(session: SecureSession): boolean {
  if (!session.lockedOutUntil) {
    return false;
  }
  return Date.now() < session.lockedOutUntil;
}

/**
 * Get remaining lockout time in milliseconds.
 */
export function getLockoutRemaining(session: SecureSession): number {
  if (!session.lockedOutUntil) {
    return 0;
  }
  return Math.max(0, session.lockedOutUntil - Date.now());
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

function generateSessionId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// ═══════════════════════════════════════════════════════════════════════════
// SENSITIVE DATA WRAPPER
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Wrapper for sensitive data that auto-zeros on disposal.
 */
export class SecureBuffer {
  private _data: Uint8Array;
  private _disposed: boolean = false;

  constructor(data: Uint8Array) {
    // Copy data to prevent external references
    this._data = new Uint8Array(data.length);
    this._data.set(data);
  }

  /**
   * Get a copy of the data (original stays protected).
   */
  get data(): Uint8Array {
    if (this._disposed) {
      throw new Error('SecureBuffer has been disposed');
    }
    const copy = new Uint8Array(this._data.length);
    copy.set(this._data);
    return copy;
  }

  /**
   * Get data length without exposing contents.
   */
  get length(): number {
    return this._data.length;
  }

  /**
   * Check if buffer has been disposed.
   */
  get isDisposed(): boolean {
    return this._disposed;
  }

  /**
   * Zero and dispose the buffer.
   */
  dispose(): void {
    if (!this._disposed) {
      zeroMemory(this._data);
      this._disposed = true;
    }
  }

  /**
   * Execute a function with the data, then dispose.
   */
  async useAndDispose<T>(fn: (data: Uint8Array) => Promise<T>): Promise<T> {
    try {
      return await fn(this._data);
    } finally {
      this.dispose();
    }
  }
}

/**
 * Create a SecureBuffer from data.
 */
export function secureBuffer(data: Uint8Array): SecureBuffer {
  return new SecureBuffer(data);
}
