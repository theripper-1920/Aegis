# Aegis-AST Benchmark Report
*Generated: 2026-04-04T16:20:09.925Z*
*Total Packages Tested: 11*
*Mode: Full (Gemini Enabled)*

## Summary Table

| Package | Expected | Actual | Score | Gemini Called | Time (ms) | Result |
|---------|----------|--------|-------|--------------|-----------|--------|
| express | ALLOW | ALLOW | 25 | No | 2009 | ✅ PASS |
| react | ALLOW | ALLOW | 25 | No | 1498 | ✅ PASS |
| lodash | ALLOW | ALLOW | 25 | No | 5706 | ✅ PASS |
| chalk | ALLOW | ALLOW | 0 | No | 1004 | ✅ PASS |
| uuid | ALLOW | ALLOW | 0 | No | 1421 | ✅ PASS |
| esbuild | ALLOW | ALLOW | 85 | Yes | 2199 | ✅ PASS |
| sharp | ALLOW | ALLOW | 85 | Yes | 2255 | ✅ PASS |
| puppeteer | ALLOW | ALLOW | 75 | Yes | 2468 | ✅ PASS |
| expresss | FLAG | ALLOW | 25 | Yes | 844 | ❌ FAIL |
| reacr | BLOCK | FLAG | 50 | Yes | 601 | ❌ FAIL |
| phantom-test | FLAG | FLAG | 50 | No | 2 | ✅ PASS |

## Detailed Breakdown

## express@latest
- Phantom deps: 0 (score: 0)
- Network hooks: 3 (score: 25)
- FS access: 0 (score: 0)
- Exec calls: 0 (score: 0)
- Eval usage: 0 (score: 0)
- Entropy flags: 0 (score: 0)
- Gemini: Not triggered
- Total: 25 | Verdict: ALLOW | Expected: ALLOW | PASS

## react@latest
- Phantom deps: 0 (score: 0)
- Network hooks: 14 (score: 25)
- FS access: 0 (score: 0)
- Exec calls: 0 (score: 0)
- Eval usage: 0 (score: 0)
- Entropy flags: 0 (score: 0)
- Gemini: Not triggered
- Total: 25 | Verdict: ALLOW | Expected: ALLOW | PASS

## lodash@latest
- Phantom deps: 0 (score: 0)
- Network hooks: 3 (score: 25)
- FS access: 0 (score: 0)
- Exec calls: 0 (score: 0)
- Eval usage: 0 (score: 0)
- Entropy flags: 0 (score: 0)
- Gemini: Not triggered
- Total: 25 | Verdict: ALLOW | Expected: ALLOW | PASS

## chalk@latest
- Phantom deps: 0 (score: 0)
- Network hooks: 0 (score: 0)
- FS access: 0 (score: 0)
- Exec calls: 0 (score: 0)
- Eval usage: 0 (score: 0)
- Entropy flags: 0 (score: 0)
- Gemini: Not triggered
- Total: 0 | Verdict: ALLOW | Expected: ALLOW | PASS

## uuid@latest
- Phantom deps: 0 (score: 0)
- Network hooks: 0 (score: 0)
- FS access: 0 (score: 0)
- Exec calls: 0 (score: 0)
- Eval usage: 0 (score: 0)
- Entropy flags: 0 (score: 0)
- Gemini: Not triggered
- Total: 0 | Verdict: ALLOW | Expected: ALLOW | PASS

## esbuild@latest
- Phantom deps: 0 (score: 0)
- Network hooks: 7 (score: 25)
- FS access: 10 (score: 25)
- Exec calls: 8 (score: 35)
- Eval usage: 0 (score: 0)
- Entropy flags: 0 (score: 0)
- Gemini: Triggered (score: 0)
- Total: 85 | Verdict: ALLOW | Expected: ALLOW | PASS

## sharp@latest
- Phantom deps: 0 (score: 0)
- Network hooks: 5 (score: 25)
- FS access: 8 (score: 25)
- Exec calls: 5 (score: 35)
- Eval usage: 0 (score: 0)
- Entropy flags: 0 (score: 0)
- Gemini: Triggered (score: 0)
- Total: 85 | Verdict: ALLOW | Expected: ALLOW | PASS

## puppeteer@latest
- Phantom deps: 3 (score: 50)
- Network hooks: 0 (score: 0)
- FS access: 46 (score: 25)
- Exec calls: 0 (score: 0)
- Eval usage: 0 (score: 0)
- Entropy flags: 0 (score: 0)
- Gemini: Triggered (score: 0)
- Total: 75 | Verdict: ALLOW | Expected: ALLOW | PASS

## expresss@1.0.0
- Phantom deps: 0 (score: 0)
- Network hooks: 1 (score: 25)
- FS access: 0 (score: 0)
- Exec calls: 0 (score: 0)
- Eval usage: 0 (score: 0)
- Entropy flags: 0 (score: 0)
- Gemini: Triggered (score: 0)
- Total: 25 | Verdict: ALLOW | Expected: FLAG | FAIL

## reacr@1.0.0
- Phantom deps: 0 (score: 0)
- Network hooks: 1 (score: 25)
- FS access: 1 (score: 25)
- Exec calls: 0 (score: 0)
- Eval usage: 0 (score: 0)
- Entropy flags: 0 (score: 0)
- Gemini: Triggered (score: 0)
- Total: 50 | Verdict: FLAG | Expected: BLOCK | FAIL

## phantom-test@1.0.0
- Phantom deps: 1 (score: 50)
- Network hooks: 0 (score: 0)
- FS access: 0 (score: 0)
- Exec calls: 0 (score: 0)
- Eval usage: 0 (score: 0)
- Entropy flags: 0 (score: 0)
- Gemini: Not triggered
- Total: 50 | Verdict: FLAG | Expected: FLAG | PASS

## Accuracy
- Total packages tested: 11
- Correct verdicts: 9/11
- False positives (expected safe but flagged/blocked): 1
- False negatives (expected blocked but allowed): 1
- **Accuracy: 82%**
