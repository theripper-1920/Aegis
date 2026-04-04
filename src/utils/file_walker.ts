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
 * Strips inline trailing comments from a line, returning only the code portion.
 *
 * Handles two forms:
 *   1. Trailing `// comment` — stripped when preceded by whitespace.
 *      Using `\s+` avoids stripping `://` which appears in URL strings like
 *      `fetch('https://api.com')` — no whitespace precedes the `//` there.
 *   2. Inline `/* comment *\/` blocks — removed wherever they appear.
 *
 * Note: does not handle `//` inside quoted strings (e.g. `'hello // world'`),
 * but that edge case is rare in practice and acceptable for static heuristics.
 */
export function stripInlineComments(line: string): string {
  // Remove /* ... */ inline block comments first
  let stripped = line.replace(/\/\*.*?\*\//g, '');
  // Remove trailing // comments preceded by whitespace
  // \s+ ensures we don't strip :// in URL string literals
  stripped = stripped.replace(/\s+\/\/.*$/, '');
  return stripped;
}

/**
 * Replaces the CONTENTS of string literals with a neutral placeholder.
 *
 * This prevents false positives where dangerous keywords appear inside
 * quoted strings — e.g. eslint rule descriptions that mention "eval()"
 * or "child_process" as documentation text rather than actual code.
 *
 * Before: description: "Disallow the use of eval()",
 * After:  description: "~~STR~~",
 *
 * Handles single-quoted, double-quoted, and template literals.
 * Preserves the quote delimiters so subsequent patterns can still
 * distinguish string vs non-string positions.
 *
 * Limitation: does not handle multi-line template literals — those are
 * split into individual lines before reaching here, so any backtick
 * content on a single line is stripped correctly.
 */
export function stripStringLiterals(line: string): string {
  return line
    .replace(/"(?:[^"\\]|\\.)*"/g,  '"~~STR~~"')
    .replace(/'(?:[^'\\]|\\.)*'/g,  "'~~STR~~'")
    .replace(/`(?:[^`\\]|\\.)*`/g,  '`~~STR~~`');
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
  'examples', 'docs', 'fixtures', 'spec', '__mocks__', 'demo',
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
        if (entry.name.endsWith('.d.ts')) continue; // type-only, never executable
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
