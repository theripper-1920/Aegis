/**
 * End-to-end integration test for P1 + P2 + P3.
 * Tests the full pipeline: fetch → scan → score → decide → log
 *
 * Run: npx ts-node --compiler-options '{"module":"commonjs","strict":false}' tests/e2e_test.ts
 */

import * as dotenv from 'dotenv';
dotenv.config();

import { fetchPackage, cleanup } from '../src/core/fetcher';
import { extractImports } from '../src/core/imports';
import { compareDependencies } from '../src/core/comparator';
import { scanScripts } from '../src/scanner/scripts';
import { scanNetwork } from '../src/scanner/network';
import { scanEntropy } from '../src/scanner/entropy';
import { scanFsAccess } from '../src/scanner/fs_access';
import { scanExec } from '../src/scanner/exec';
import { scanEval } from '../src/scanner/eval';
import { runGeminiAnalysis } from '../src/scanner/gemini';
import { calculateFullRisk, FullScanInput, ScannerOutput } from '../src/core/risk_engine';
import { applyFullPolicy } from '../src/core/policy';
import { initDatabase, logScan, closeDatabase } from '../src/utils/logger';

async function runE2E(packageName: string, version: string = 'latest') {
  console.log('═══════════════════════════════════════════════════');
  console.log(`  AEGIS E2E TEST: ${packageName}@${version}`);
  console.log('═══════════════════════════════════════════════════\n');

  // ── 1. Fetch ──────────────────────────────────────────
  console.log('[1/7] Fetching package...');
  let fetchResult;
  try {
    fetchResult = await fetchPackage(packageName, version);
    console.log(`  ✅ Extracted to: ${fetchResult.extractedPath}`);
    console.log(`  📦 Dependencies: ${Object.keys(fetchResult.metadata.dependencies || {}).join(', ') || 'none'}\n`);
  } catch (e: any) {
    console.error(`  ❌ Fetch failed: ${e.message}`);
    return;
  }

  const dir = fetchResult.extractedPath;

  // ── 2. Import extraction + comparison ─────────────────
  console.log('[2/7] Extracting imports & comparing...');
  const imports = await extractImports(dir);
  const comparator = compareDependencies(fetchResult.metadata, imports);
  console.log(`  Used: ${comparator.usedDependencies.join(', ') || 'none'}`);
  console.log(`  🔴 Phantom: ${comparator.phantom.join(', ') || 'none'}`);
  console.log(`  ⚠️  Missing: ${comparator.missing.join(', ') || 'none'}\n`);

  // ── 3. Run all scanners ───────────────────────────────
  console.log('[3/7] Running security scanners...');
  const [scripts, network, entropy, fs, exec, evalResult] = await Promise.all([
    scanScripts(dir),
    scanNetwork(dir),
    scanEntropy(dir),
    scanFsAccess(dir),
    scanExec(dir),
    scanEval(dir),
  ]);

  const scannerOutput: ScannerOutput = {
    scripts: scripts.scripts,
    network: network.network,
    entropy: entropy.entropy,
    fs: fs.fs,
    exec: exec.exec,
    eval: evalResult.eval,
  };

  // Count how many scanners flagged something
  let flagCount = 0;
  for (const [name, findings] of Object.entries(scannerOutput)) {
    if ((findings as string[]).length > 0) flagCount++;
    console.log(`  ${(findings as string[]).length > 0 ? '🔴' : '✅'} ${name}: ${(findings as string[]).length} finding(s)`);
  }
  console.log(`  Total scanners flagged: ${flagCount}\n`);

  // ── 4. Gemini (conditional) ───────────────────────────
  console.log('[4/7] Gemini AI analysis...');
  const geminiResult = await runGeminiAnalysis(
    flagCount,
    packageName,
    scannerOutput.scripts.length > 0 ? scannerOutput.scripts.join('\n') : undefined,
    { similarTo: packageName, downloads: 0, ageDays: 0 }
  );
  if (geminiResult) {
    console.log(`  Typosquat: ${geminiResult.typosquat?.verdict || 'not checked'}`);
    console.log(`  Script: ${geminiResult.script?.verdict || 'not checked'}\n`);
  } else {
    console.log('  ⏩ Skipped (fewer than 2 scanners flagged)\n');
  }

  // ── 5. Risk scoring ───────────────────────────────────
  console.log('[5/7] Calculating risk score...');
  const input: FullScanInput = {
    packageName,
    packageVersion: version,
    ecosystem: 'npm',
    phantomDeps: comparator.phantom,
    scannerOutput,
    gemini: geminiResult,
  };
  const riskScore = calculateFullRisk(input);
  console.log(`  Total score: ${riskScore.total}`);
  console.log(`  Breakdown:`, riskScore.breakdown, '\n');

  // ── 6. Policy decision ────────────────────────────────
  console.log('[6/7] Applying policy...');
  const policy = applyFullPolicy(riskScore, input);
  console.log(`  Decision: ${policy.decision}`);
  console.log(`  Reasons:`);
  for (const r of policy.reasons) {
    console.log(`    ${r}`);
  }
  console.log();

  // ── 7. MongoDB logging ────────────────────────────────
  console.log('[7/7] Logging to MongoDB...');
  try {
    await initDatabase();
    await logScan(input, riskScore, policy.decision, policy.reasons);
    console.log('  ✅ Logged to MongoDB\n');
  } catch (e: any) {
    console.log(`  ⚠️  MongoDB: ${e.message}\n`);
  }

  // ── Cleanup ───────────────────────────────────────────
  await cleanup(dir);
  await closeDatabase();

  console.log('═══════════════════════════════════════════════════');
  console.log(`  RESULT: ${packageName}@${version} → ${policy.decision} (score: ${riskScore.total})`);
  console.log('═══════════════════════════════════════════════════');
}

// Run with a clean package first
runE2E('is-odd', 'latest').catch(console.error);
