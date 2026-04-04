/**
 * ═══════════════════════════════════════════════════════════
 *  AEGIS-AST — File Walker Utility
 *  Shared utility for recursively walking source files.
 *  Used by Person 1 (imports) and Person 2 (all scanners).
 * ═══════════════════════════════════════════════════════════
 */

import * as fs from 'fs';
import * as path from 'path';

/**
 * Checks if a line is a comment (single-line // or block comment /* or *).
 * Used by scanners to skip false positives from URLs in documentation.
 */
export function isCommentLine(line: string): boolean {
  const trimmed = line.trim();
  return (
    trimmed.startsWith('//') ||
    trimmed.startsWith('/*') ||
    trimmed.startsWith('*') ||
    trimmed.startsWith('*/') ||
    trimmed.startsWith('#')
  );
}

/**
 * Checks if a file is minified (.min.js, .min.cjs, etc.).
 * Minified code naturally has high entropy — not obfuscation.
 */
export function isMinifiedFile(filePath: string): boolean {
  return /\.min\.[cm]?js$/i.test(filePath);
}

/** File extensions to scan */
export const SOURCE_EXTENSIONS = new Set([
  '.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx',
]);

/** Directories to skip during walking */
export const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'coverage', '__tests__', 'test',
]);

export interface SourceFile {
  absolutePath: string;
  relativePath: string;
  content: string;
}

/**
 * Recursively walks a directory and returns all source files.
 *
 * @param rootDir - Root directory to walk
 * @returns Array of SourceFile objects with path and content
 */
export function walkSourceFiles(rootDir: string): SourceFile[] {
  const results: SourceFile[] = [];

  function walk(dir: string): void {
    if (!fs.existsSync(dir)) return;

    const entries = fs.readdirSync(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) {
          walk(fullPath);
        }
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (SOURCE_EXTENSIONS.has(ext)) {
          results.push({
            absolutePath: fullPath,
            relativePath: path.relative(rootDir, fullPath),
            content: fs.readFileSync(fullPath, 'utf-8'),
          });
        }
      }
    }
  }

  walk(rootDir);
  return results;
}

/**
 * Reads all files in a directory (including non-source files).
 * Useful for scanning package.json, README, etc.
 */
export function walkAllFiles(rootDir: string): SourceFile[] {
  const results: SourceFile[] = [];

  function walk(dir: string): void {
    if (!fs.existsSync(dir)) return;

    const entries = fs.readdirSync(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) {
          walk(fullPath);
        }
      } else if (entry.isFile()) {
        try {
          results.push({
            absolutePath: fullPath,
            relativePath: path.relative(rootDir, fullPath),
            content: fs.readFileSync(fullPath, 'utf-8'),
          });
        } catch {
          // Skip binary files that can't be read as UTF-8
        }
      }
    }
  }

  walk(rootDir);
  return results;
}
