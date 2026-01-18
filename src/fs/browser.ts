/**
 * Omnituum FS - Browser File Utilities
 *
 * Utilities for handling files in the browser environment:
 * - Drag and drop support
 * - File download/upload
 * - Blob/URL handling
 */

import { OQE_MIME_TYPE, OQE_EXTENSION, isOQEFile } from './format';
import { OQEEncryptResult, OQEDecryptResult } from './types';

// Helper to convert Uint8Array to a format compatible with Blob constructor
function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  // Handle SharedArrayBuffer or offset views by copying
  if (data.buffer instanceof SharedArrayBuffer || data.byteOffset !== 0 || data.byteLength !== data.buffer.byteLength) {
    const copy = new ArrayBuffer(data.byteLength);
    new Uint8Array(copy).set(data);
    return copy;
  }
  return data.buffer as ArrayBuffer;
}

// ═══════════════════════════════════════════════════════════════════════════
// FILE DOWNLOAD
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Download encrypted file to user's device.
 *
 * @param result - Encryption result from encryptFile()
 */
export function downloadEncryptedFile(result: OQEEncryptResult): void {
  const blob = new Blob([toArrayBuffer(result.data)], { type: OQE_MIME_TYPE });
  downloadBlob(blob, result.filename);
}

/**
 * Download decrypted file to user's device.
 *
 * @param result - Decryption result from decryptFile()
 */
export function downloadDecryptedFile(result: OQEDecryptResult): void {
  const mimeType = result.mimeType || 'application/octet-stream';
  const blob = new Blob([toArrayBuffer(result.data)], { type: mimeType });
  downloadBlob(blob, result.filename);
}

/**
 * Download a Blob as a file.
 */
export function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);

  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.style.display = 'none';

  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);

  // Clean up URL after download starts
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/**
 * Download bytes as a file.
 */
export function downloadBytes(data: Uint8Array, filename: string, mimeType?: string): void {
  const blob = new Blob([toArrayBuffer(data)], { type: mimeType || 'application/octet-stream' });
  downloadBlob(blob, filename);
}

// ═══════════════════════════════════════════════════════════════════════════
// FILE READING
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Read a File object as Uint8Array.
 */
export async function readFile(file: File): Promise<Uint8Array> {
  const buffer = await file.arrayBuffer();
  return new Uint8Array(buffer);
}

/**
 * Read a File object as text.
 */
export async function readFileAsText(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result as string);
    reader.onerror = () => reject(reader.error);
    reader.readAsText(file);
  });
}

/**
 * Read a File object as Data URL.
 */
export async function readFileAsDataURL(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result as string);
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(file);
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// DRAG AND DROP
// ═══════════════════════════════════════════════════════════════════════════

export interface DropZoneOptions {
  /** Element to attach drop zone to */
  element: HTMLElement;
  /** Called when valid files are dropped */
  onDrop: (files: File[]) => void;
  /** Called when drag enters */
  onDragEnter?: () => void;
  /** Called when drag leaves */
  onDragLeave?: () => void;
  /** Filter for accepted file types (e.g., ['image/*', '.pdf']) */
  accept?: string[];
  /** Allow multiple files */
  multiple?: boolean;
}

/**
 * Create a drop zone for file drag and drop.
 * Returns a cleanup function to remove listeners.
 */
export function createDropZone(options: DropZoneOptions): () => void {
  const { element, onDrop, onDragEnter, onDragLeave, accept, multiple = true } = options;

  let dragCounter = 0;

  const handleDragEnter = (e: DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounter++;
    if (dragCounter === 1) {
      onDragEnter?.();
    }
  };

  const handleDragLeave = (e: DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounter--;
    if (dragCounter === 0) {
      onDragLeave?.();
    }
  };

  const handleDragOver = (e: DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleDrop = (e: DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounter = 0;
    onDragLeave?.();

    const files = Array.from(e.dataTransfer?.files || []);

    // Filter by accept types if specified
    let filteredFiles = files;
    if (accept && accept.length > 0) {
      filteredFiles = files.filter((file) => {
        return accept.some((pattern) => {
          if (pattern.startsWith('.')) {
            return file.name.toLowerCase().endsWith(pattern.toLowerCase());
          }
          if (pattern.endsWith('/*')) {
            const type = pattern.slice(0, -2);
            return file.type.startsWith(type);
          }
          return file.type === pattern;
        });
      });
    }

    // Limit to single file if not multiple
    if (!multiple && filteredFiles.length > 1) {
      filteredFiles = [filteredFiles[0]];
    }

    if (filteredFiles.length > 0) {
      onDrop(filteredFiles);
    }
  };

  element.addEventListener('dragenter', handleDragEnter);
  element.addEventListener('dragleave', handleDragLeave);
  element.addEventListener('dragover', handleDragOver);
  element.addEventListener('drop', handleDrop);

  // Return cleanup function
  return () => {
    element.removeEventListener('dragenter', handleDragEnter);
    element.removeEventListener('dragleave', handleDragLeave);
    element.removeEventListener('dragover', handleDragOver);
    element.removeEventListener('drop', handleDrop);
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// FILE INPUT
// ═══════════════════════════════════════════════════════════════════════════

export interface FileInputOptions {
  /** Filter for accepted file types */
  accept?: string[];
  /** Allow multiple files */
  multiple?: boolean;
}

/**
 * Open file picker dialog and return selected files.
 */
export function openFilePicker(options: FileInputOptions = {}): Promise<File[]> {
  return new Promise((resolve) => {
    const input = document.createElement('input');
    input.type = 'file';
    input.multiple = options.multiple ?? false;

    if (options.accept && options.accept.length > 0) {
      input.accept = options.accept.join(',');
    }

    input.onchange = () => {
      const files = Array.from(input.files || []);
      resolve(files);
    };

    input.oncancel = () => {
      resolve([]);
    };

    input.click();
  });
}

/**
 * Open file picker for OQE files specifically.
 */
export function openOQEFilePicker(multiple = false): Promise<File[]> {
  return openFilePicker({
    accept: [OQE_EXTENSION, OQE_MIME_TYPE],
    multiple,
  });
}

/**
 * Open file picker for any file to encrypt.
 */
export function openFileToEncrypt(multiple = false): Promise<File[]> {
  return openFilePicker({ multiple });
}

// ═══════════════════════════════════════════════════════════════════════════
// BLOB UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Create a Blob from encryption result.
 */
export function encryptResultToBlob(result: OQEEncryptResult): Blob {
  return new Blob([toArrayBuffer(result.data)], { type: OQE_MIME_TYPE });
}

/**
 * Create a Blob from decryption result.
 */
export function decryptResultToBlob(result: OQEDecryptResult): Blob {
  const mimeType = result.mimeType || 'application/octet-stream';
  return new Blob([toArrayBuffer(result.data)], { type: mimeType });
}

/**
 * Create an object URL for a Blob.
 * Remember to call URL.revokeObjectURL() when done.
 */
export function createObjectURL(blob: Blob): string {
  return URL.createObjectURL(blob);
}

/**
 * Create a Data URL from bytes.
 */
export async function bytesToDataURL(data: Uint8Array, mimeType: string): Promise<string> {
  const blob = new Blob([toArrayBuffer(data)], { type: mimeType });
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result as string);
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(blob);
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// FILE INFO
// ═══════════════════════════════════════════════════════════════════════════

export interface FileInfo {
  /** Filename */
  name: string;
  /** File size in bytes */
  size: number;
  /** MIME type */
  type: string;
  /** Last modified timestamp */
  lastModified: number;
  /** Is this an OQE file? */
  isOQE: boolean;
  /** Human-readable size */
  sizeFormatted: string;
}

/**
 * Get information about a file.
 */
export function getFileInfo(file: File): FileInfo {
  return {
    name: file.name,
    size: file.size,
    type: file.type || 'application/octet-stream',
    lastModified: file.lastModified,
    isOQE: isOQEFile(file.name),
    sizeFormatted: formatFileSize(file.size),
  };
}

/**
 * Format file size for display.
 */
export function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 B';

  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const k = 1024;
  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return `${(bytes / Math.pow(k, i)).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

// ═══════════════════════════════════════════════════════════════════════════
// CLIPBOARD
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Copy text to clipboard.
 */
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Fallback for older browsers
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.left = '-9999px';
    document.body.appendChild(textarea);
    textarea.select();
    const success = document.execCommand('copy');
    document.body.removeChild(textarea);
    return success;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// ENVIRONMENT DETECTION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Check if running in a browser environment.
 */
export function isBrowser(): boolean {
  return typeof window !== 'undefined' && typeof document !== 'undefined';
}

/**
 * Check if Web Crypto API is available.
 */
export function isWebCryptoAvailable(): boolean {
  return typeof globalThis.crypto !== 'undefined' && typeof globalThis.crypto.subtle !== 'undefined';
}

/**
 * Check if File API is available.
 */
export function isFileAPIAvailable(): boolean {
  return typeof File !== 'undefined' && typeof FileReader !== 'undefined';
}

/**
 * Check if drag and drop is supported.
 */
export function isDragDropSupported(): boolean {
  const div = document.createElement('div');
  return 'draggable' in div || ('ondragstart' in div && 'ondrop' in div);
}
