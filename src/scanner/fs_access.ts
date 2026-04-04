/**
 * ═══════════════════════════════════════════════════════════
 *  AEGIS-AST — File System Access Scanner
 *  Owner: Person 2 (Security Detection Engine)
 *
 *  Scans JS/TS source files for suspicious filesystem access —
 *  sensitive file reads, env secret access, and dangerous fs APIs.
 * ═══════════════════════════════════════════════════════════
 */

import * as fs from 'fs';
import * as path from 'path';
import { walkSourceFiles, stripInlineComments } from '../utils/file_walker';

// Non-global regexes (no /g flag) — safe to reuse across lines without resetting lastIndex.
// Only patterns that point to genuinely sensitive resources.
// Removed: process.env (replaced by whitelist below), __dirname, __filename,
//          readdirSync, existsSync, os.tmpdir() — all standard Node.js primitives.
// Kept: readFileSync (real attacks: readFileSync('/etc/passwd')).
const FS_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /\/etc\/passwd/,       label: '/etc/passwd' },
  { pattern: /\/etc\/shadow/,       label: '/etc/shadow' },
  { pattern: /~\/\.ssh/,            label: '~/.ssh' },
  { pattern: /\.ssh\/id_rsa/,       label: '.ssh/id_rsa' },
  { pattern: /os\.homedir\s*\(\)/,  label: 'os.homedir()' },
  { pattern: /readFileSync\s*\(/,   label: 'readFileSync' },
  { pattern: /fs\.watch\s*\(/,      label: 'fs.watch' },
];

// Env vars that are universally benign — don't flag these.
const SAFE_ENV_VARS = new Set([
  'NODE_ENV', 'PORT', 'DEBUG', 'HOME', 'PATH',
  'CI', 'TERM', 'LANG', 'TZ', 'NODE_DEBUG',
]);

/**
 * Returns deduplicated labels for all fs patterns found in a single line.
 */
function getMatchedLabels(line: string): string[] {
  const seen = new Set<string>();
  for (const { pattern, label } of FS_PATTERNS) {
    if (pattern.test(line) && !seen.has(label)) {
      seen.add(label);
    }
  }
  return Array.from(seen);
}

/**
 * Scans all JS/TS source files in packageDir for suspicious filesystem access.
 *
 * @param packageDir - Path to the extracted package root
 * @returns Object with `fs` array of human-readable finding strings.
 *          Returns { fs: [] } if nothing found. Never throws.
 */
export async function scanFsAccess(
  packageDir: string
): Promise<{ fs: string[] }> {
  let files;
  try {
    files = walkSourceFiles(packageDir);
  } catch {
    return { fs: [] };
  }

  if (files.length === 0) return { fs: [] };

  const findings: string[] = [];

  for (const file of files) {
    try {
      const lines = file.content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const trimmed = line.trim();
        const relPath = file.relativePath;
        const lineNum = i + 1;
        const code = stripInlineComments(line); // strip trailing comments before matching

        const matchedLabels = getMatchedLabels(code);

        // Smart process.env check: flag bare access or unknown env var names.
        // Bare process.env (no key) = iterating all env vars = exfiltration pattern.
        // process.env.UNKNOWN_KEY = potential secret harvesting.
        const envMatch = code.match(/process\.env(?:\.([A-Z_a-z][A-Z0-9_a-z]*))?/);
        if (envMatch) {
          const key = envMatch[1]; // undefined when bare process.env
          if (!key || !SAFE_ENV_VARS.has(key.toUpperCase())) {
            matchedLabels.push(`process.env${key ? '.' + key : ' (bare)'}`);
          }
        }

        if (matchedLabels.length === 0) continue;

        findings.push(
          `${relPath}:${lineNum} — ${trimmed} — contains ${matchedLabels.join(', ')}`
        );
      }
    } catch {
      // Skip files that error during processing
    }
  }

  return { fs: findings };
}

// ─── Self-test ────────────────────────────────────────────────────────────────
// Run directly:  npx ts-node src/scanner/fs_access.ts

if (require.main === module) {
  (async () => {
    const testDir = '/tmp/aegis-fs-test';
    const srcDir = path.join(testDir, 'lib');

    fs.mkdirSync(srcDir, { recursive: true });

    fs.writeFileSync(
      path.join(srcDir, 'index.js'),
      [
        // Clean lines — should NOT be flagged
        `const x = 1 + 1;`,
        `console.log('hello world');`,
        // Suspicious — SHOULD be flagged
        `const shadow = readFileSync('/etc/shadow', 'utf8');`,
        `const passwd = readFileSync('/etc/passwd', 'utf8');`,
        `const key = readFileSync(os.homedir() + '/.ssh/id_rsa', 'utf8');`,
        `const token = process.env.NPM_TOKEN;`,
        `const files = readdirSync(__dirname);`,
        `fs.watch(__filename, handler);`,
        `const tmp = os.tmpdir();`,
        `if (existsSync('/etc/shadow')) { steal(); }`,
      ].join('\n')
    );

    console.log('Running scanFsAccess on fake malicious package...\n');
    const result = await scanFsAccess(testDir);

    if (result.fs.length === 0) {
      console.log('No findings (unexpected — check patterns)');
    } else {
      for (const finding of result.fs) {
        console.log('  FLAGGED:', finding);
      }
    }

    fs.rmSync(testDir, { recursive: true, force: true });
    console.log('\nCleanup done.');
  })();
}
