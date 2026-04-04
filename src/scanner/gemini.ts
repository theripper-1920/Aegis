/**
 * ═══════════════════════════════════════════════════════════
 *  AEGIS-AST — Gemini AI Scanner (Conditional)
 *
 *  Only invoked when 2+ local scanners flag something.
 *  Two API calls:
 *    1. classifyTyposquat() — is this a typosquat/slopsquat?
 *    2. analyzeScript()     — is this script malicious?
 *
 *  Responses are parsed safely with JSON fallback.
 *  Pre-cached results can be used for demo packages.
 * ═══════════════════════════════════════════════════════════
 */

import { GoogleGenerativeAI } from '@google/generative-ai';
import { GeminiTyposquatResult, GeminiScriptResult, GeminiResults } from '../core/risk_engine';

// ─── Init ───────────────────────────────────────────────────

let genAI: GoogleGenerativeAI | null = null;

function getModel() {
  if (!genAI) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      console.warn('⚠️  GEMINI_API_KEY not set — Gemini analysis disabled.');
      return null;
    }
    genAI = new GoogleGenerativeAI(apiKey);
  }
  return genAI.getGenerativeModel({ model: 'gemini-2.0-flash' });
}

// ─── Safe JSON parsing ──────────────────────────────────────

/**
 * Strips markdown code fences and parses JSON safely.
 * Gemini sometimes returns ```json ... ``` around its response.
 */
function safeParseJSON<T>(text: string): T | null {
  try {
    // Strip markdown code fences if present
    let cleaned = text.trim();
    if (cleaned.startsWith('```')) {
      cleaned = cleaned.replace(/^```(?:json)?\s*\n?/, '').replace(/\n?```\s*$/, '');
    }
    return JSON.parse(cleaned) as T;
  } catch {
    return null;
  }
}

// ─── API Functions ──────────────────────────────────────────

/**
 * Classifies whether a package is a typosquat or slopsquat.
 *
 * @param name       - Package name to classify
 * @param downloads  - Weekly download count
 * @param ageDays    - Days since first published
 * @param similarTo  - Name of the popular package it resembles
 */
export async function classifyTyposquat(
  name: string,
  downloads: number,
  ageDays: number,
  similarTo: string
): Promise<GeminiTyposquatResult> {
  const fallback: GeminiTyposquatResult = {
    verdict: 'legitimate',
    confidence: 0,
    reasoning: 'Gemini analysis unavailable',
  };

  const model = getModel();
  if (!model) return fallback;

  const prompt = `You are a supply-chain security analyst. Analyze this npm package for typosquatting or slopsquatting.

Package name: "${name}"
Weekly downloads: ${downloads}
Days since published: ${ageDays}
Similar popular package: "${similarTo}" (millions of weekly downloads)

Is this package likely legitimate, a typosquat (intentional name mimicry), or a slopsquat (AI-hallucinated package name)?

Respond ONLY with valid JSON, no markdown, no explanation:
{"verdict": "legitimate" | "typosquat" | "slopsquat", "confidence": 0.0-1.0, "reasoning": "brief explanation"}`;

  try {
    const result = await model.generateContent(prompt);
    const text = result.response.text();
    const parsed = safeParseJSON<GeminiTyposquatResult>(text);

    if (parsed && parsed.verdict && typeof parsed.confidence === 'number') {
      return parsed;
    }
    return { ...fallback, reasoning: `Gemini returned unparseable response: ${text.substring(0, 100)}` };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    console.warn(`⚠️  Gemini typosquat classification failed: ${msg}`);
    return fallback;
  }
}

/**
 * Analyzes a script for malicious intent.
 *
 * @param scriptContent - The content of the flagged script
 * @param context       - Additional context (e.g., "postinstall hook")
 */
export async function analyzeScript(
  scriptContent: string,
  context: string = 'install script'
): Promise<GeminiScriptResult> {
  const fallback: GeminiScriptResult = {
    verdict: 'safe',
    risk_level: 'unknown',
    techniques: [],
    reasoning: 'Gemini analysis unavailable',
  };

  const model = getModel();
  if (!model) return fallback;

  // Truncate very long scripts to avoid token limits
  const truncated = scriptContent.length > 3000
    ? scriptContent.substring(0, 3000) + '\n... [truncated]'
    : scriptContent;

  const prompt = `You are a malware analyst. Analyze this ${context} for malicious intent.

Flag any of these techniques:
- Hidden shell execution
- Base64-encoded payloads
- Network requests to hardcoded endpoints
- Credential file access (.ssh, .aws, .env, /etc/passwd)
- Environment variable exfiltration (process.env, os.environ)
- Obfuscated code (XOR, char code manipulation, string reversal)
- Data exfiltration to external servers

Script content:
\`\`\`
${truncated}
\`\`\`

Respond ONLY with valid JSON, no markdown, no explanation:
{"verdict": "safe" | "suspicious" | "malicious", "risk_level": "low" | "medium" | "high" | "critical", "techniques": ["list", "of", "techniques"], "reasoning": "brief explanation"}`;

  try {
    const result = await model.generateContent(prompt);
    const text = result.response.text();
    const parsed = safeParseJSON<GeminiScriptResult>(text);

    if (parsed && parsed.verdict && Array.isArray(parsed.techniques)) {
      return parsed;
    }
    return { ...fallback, reasoning: `Gemini returned unparseable response: ${text.substring(0, 100)}` };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    console.warn(`⚠️  Gemini script analysis failed: ${msg}`);
    return fallback;
  }
}

/**
 * Runs both Gemini analyses if conditions are met.
 * Only fires when 2+ scanners have flagged something.
 *
 * @param flagCount   - Number of scanners that flagged something
 * @param packageName - Package name (for typosquat check)
 * @param scriptContent - Content of flagged script (for analysis)
 * @param metadata    - Optional package metadata for typosquat context
 */
export async function runGeminiAnalysis(
  flagCount: number,
  packageName: string,
  scriptContent?: string,
  metadata?: { downloads?: number; ageDays?: number; similarTo?: string }
): Promise<GeminiResults | null> {
  // Only fire when 2+ scanners flagged something
  if (flagCount < 2) return null;

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    console.warn('⚠️  GEMINI_API_KEY not set — skipping Gemini analysis.');
    return null;
  }

  console.log(`[Gemini] ${flagCount} scanners flagged — running AI analysis...`);

  const results: GeminiResults = {};

  // Call 1: Typosquat classification
  if (metadata?.similarTo) {
    console.log(`[Gemini] Classifying "${packageName}" for typosquatting...`);
    results.typosquat = await classifyTyposquat(
      packageName,
      metadata.downloads ?? 0,
      metadata.ageDays ?? 0,
      metadata.similarTo
    );
    console.log(`[Gemini] Verdict: ${results.typosquat.verdict} (${results.typosquat.confidence})`);
  }

  // Call 2: Script analysis
  if (scriptContent && scriptContent.trim().length > 0) {
    console.log(`[Gemini] Analyzing flagged script content...`);
    results.script = await analyzeScript(scriptContent);
    console.log(`[Gemini] Verdict: ${results.script.verdict} (${results.script.risk_level})`);
  }

  return results;
}
