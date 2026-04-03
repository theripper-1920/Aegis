/**
 * ═══════════════════════════════════════════════════════════
 * AEGIS-AST — Import Extractor
 * Owner: Person 1 (Core Engine)
 * * Responsibilities:
 * - Walk all .js/.ts files in extracted package
 * - Extract require() and import statements via regex
 * - Return deduplicated list of used dependencies
 * ═══════════════════════════════════════════════════════════
 */

import { ImportScanResult } from '../types';
import * as fsp from 'fs/promises';
import * as path from 'path';
import { builtinModules } from 'module';

/**
 * Regex patterns for extracting imports from JavaScript/TypeScript files.
 */
export const IMPORT_PATTERNS = {
  /** CommonJS require */
  REQUIRE: /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
  /** ES module import (named, default, namespace, side-effect) */
  ES_IMPORT: /import\s+(?:(?:[\w*{}\s,]+)\s+from\s+)?['"]([^'"]+)['"]/g,
  /** Dynamic import */
  DYNAMIC_IMPORT: /import\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
};

// Valid file extensions to scan
const VALID_EXTENSIONS = new Set(['.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx']);

/**
 * Extracts all imports from the source files of an extracted package.
 *
 * @param extractedPath - Path to the extracted package directory
 * @returns ImportScanResult with all found imports
 */
export async function extractImports(
  extractedPath: string
): Promise<ImportScanResult> {
  const usedDependencies = new Set<string>();
  const rawImports: Array<{ filePath: string; importName: string; line: number }> = [];

  // Helper function to recursively walk directories (Fallback if utils/file_walker is unavailable)
  async function walkFiles(dir: string): Promise<string[]> {
    let files: string[] = [];
    const entries = await fsp.readdir(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      // Skip common bloated directories to speed up scanning
      if (entry.isDirectory() && !['node_modules', '.git', 'dist', 'build'].includes(entry.name)) {
        files = files.concat(await walkFiles(fullPath));
      } else if (entry.isFile() && VALID_EXTENSIONS.has(path.extname(entry.name))) {
        files.push(fullPath);
      }
    }
    return files;
  }

  // Helper to calculate the line number of a match in file content
  function getLineNumber(content: string, matchIndex: number): number {
    return content.substring(0, matchIndex).split('\n').length;
  }

  try {
    const files = await walkFiles(extractedPath);

    for (const file of files) {
      const content = await fsp.readFile(file, 'utf-8');

      // Helper to execute regex, track raw imports, and normalize results
      const extract = (pattern: RegExp) => {
        let match;
        // Reset lastIndex because we are reusing global regexes
        pattern.lastIndex = 0;
        while ((match = pattern.exec(content)) !== null) {
          const rawImport = match[1];
          const lineNumber = getLineNumber(content, match.index);

          // Track every raw import for the report
          rawImports.push({
            filePath: file,
            importName: rawImport,
            line: lineNumber,
          });

          const normalized = normalizeImport(rawImport);
          if (normalized) {
            usedDependencies.add(normalized);
          }
        }
      };

      // 3. Apply IMPORT_PATTERNS regexes
      extract(IMPORT_PATTERNS.REQUIRE);
      extract(IMPORT_PATTERNS.ES_IMPORT);
      extract(IMPORT_PATTERNS.DYNAMIC_IMPORT);
    }

    // 5. Deduplicate (handled by Set) and return
    return {
      usedDependencies: Array.from(usedDependencies),
      rawImports,
    };
  } catch (error) {
    throw new Error(`Failed to extract imports from ${extractedPath}: ${(error as Error).message}`);
  }
}

/**
 * Normalizes a raw import string to a package name.
 * - Skips relative imports (./foo, ../bar)
 * - Handles scoped packages (@scope/pkg)
 * - Strips subpath imports (lodash/get → lodash)
 * - Ignores Node.js native built-ins (fs, path, etc.)
 */
export function normalizeImport(rawImport: string): string | null {
  // 1. Skip relative and absolute local imports
  if (rawImport.startsWith('.') || rawImport.startsWith('/')) {
    return null;
  }

  // 2. Handle 'node:' protocol prefixes (e.g., 'node:fs')
  const cleanImport = rawImport.startsWith('node:') ? rawImport.substring(5) : rawImport;

  // 3. Skip built-in Node modules (fs, path, crypto, etc.)
  if (builtinModules.includes(cleanImport)) {
    return null;
  }

  // 4. Handle scoped packages (e.g., @angular/core/testing -> @angular/core)
  if (cleanImport.startsWith('@')) {
    const parts = cleanImport.split('/');
    if (parts.length >= 2) {
      return `${parts[0]}/${parts[1]}`;
    }
    return cleanImport; // Fallback for malformed scope
  }

  // 5. Handle normal packages (e.g., lodash/fp/get -> lodash)
  return cleanImport.split('/')[0];
}