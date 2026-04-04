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
import { GeminiTyposquatResult, GeminiScriptResult, GeminiDomainVerdict, GeminiResults } from '../core/risk_engine';

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

// ─── Domain Trust Analysis ────────────────────────────────────────

/** Input structure for a single domain to analyze */
interface DomainInput {
  domain: string;
  full_url: string;
  usage_context: string;
  frequency: number;
}

/**
 * Extracts unique domains from network scanner findings.
 * Deduplicates via hashmap and counts frequency.
 */
function extractDomainsFromFindings(networkFindings: string[]): DomainInput[] {
  const domainMap = new Map<string, DomainInput>();

  const urlRegex = /https?:\/\/([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)(\/[^\s'"`,;)}\]]*)?/gi;
  const ipRegex = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;

  for (const finding of networkFindings) {
    let match;
    while ((match = urlRegex.exec(finding)) !== null) {
      const domain = match[1].toLowerCase();
      const fullUrl = match[0];
      if (domainMap.has(domain)) {
        domainMap.get(domain)!.frequency++;
      } else {
        domainMap.set(domain, { domain, full_url: fullUrl, usage_context: finding, frequency: 1 });
      }
    }
    urlRegex.lastIndex = 0;

    while ((match = ipRegex.exec(finding)) !== null) {
      const ip = match[1];
      if (ip === '127.0.0.1' || ip === '0.0.0.0') continue;
      if (domainMap.has(ip)) {
        domainMap.get(ip)!.frequency++;
      } else {
        domainMap.set(ip, { domain: ip, full_url: ip, usage_context: finding, frequency: 1 });
      }
    }
    ipRegex.lastIndex = 0;
  }

  return Array.from(domainMap.values());
}

/**
 * Analyzes domains for trust verification.
 * Acts as a security intelligence layer — classifies each domain as
 * SAFE_NECESSARY, SAFE_UNNECESSARY, SUSPICIOUS, or MALICIOUS.
 *
 * @param networkFindings - Raw string[] from scanNetwork()
 * @returns Array of domain verdicts (empty if no domains or no API key)
 */
export async function analyzeDomainTrust(
  networkFindings: string[]
): Promise<GeminiDomainVerdict[]> {
  if (!networkFindings || networkFindings.length === 0) return [];

  const domains = extractDomainsFromFindings(networkFindings);
  if (domains.length === 0) return [];

  const model = getModel();
  if (!model) return [];

  console.log(`[Gemini] Analyzing ${domains.length} unique domain(s) for trust verification...`);

  const domainList = domains.map(d => JSON.stringify(d)).join(',\n  ');

  const prompt = `You are a security intelligence module inside a package security scanner.

Your role is to ANALYZE external network domains detected in package code and act as a TRUST VERIFICATION LAYER before final risk scoring.

You will receive UNIQUE domains (deduplicated via hashmap) extracted from code.

Determine whether each domain is:
- Legitimate and necessary (SAFE_NECESSARY)
- Legitimate but unnecessary (SAFE_UNNECESSARY)
- Suspicious (SUSPICIOUS)
- Malicious (MALICIOUS)

DOMAINS TO ANALYZE:
[
  ${domainList}
]

ANALYSIS REQUIREMENTS — You MUST perform reasoning similar to a security researcher:

1. Domain Trust
   - Is this a well-known service? (Google, AWS, Cloudflare, npm registry, etc.)
   - Or an obscure / newly appearing domain?

2. Purpose Inference
   - What is this endpoint likely doing?
   - (API, analytics, telemetry, exfiltration, command-and-control)

3. Risk Signals — Check for:
   - Data collection endpoints (/collect, /track, /log)
   - Suspicious naming (exfil, c2, webhook, bot, api/hidden)
   - IP address usage instead of domain
   - Non-HTTPS usage
   - Hardcoded endpoints

4. Context Awareness
   - Does the usage_context suggest sensitive data transfer?
   - Is this necessary for functionality or suspicious?

IMPORTANT RULES:
- DO NOT give generic answers like "might be unsafe"
- You MUST justify decisions with concrete reasoning
- If domain is well-known → explicitly say why it is safe
- If suspicious → explain exact pattern
- If unsure → classify as SUSPICIOUS (not safe)
- Include at least ONE concrete signal from the domain or URL
- Reference the usage_context in reasoning
- Avoid vague statements

Respond ONLY with a valid JSON array, no markdown, no explanation:
[
  {
    "domain": "...",
    "decision": "SAFE_NECESSARY" | "SAFE_UNNECESSARY" | "SUSPICIOUS" | "MALICIOUS",
    "confidence": 0-100,
    "risk_score": 0-100,
    "reasoning": "clear, specific explanation referencing URL and context",
    "signals": {
      "known_service": true/false,
      "data_collection_pattern": true/false,
      "uses_https": true/false,
      "suspicious_keywords": ["..."],
      "ip_based": true/false
    }
  }
]`;

  try {
    const result = await model.generateContent(prompt);
    const text = result.response.text();
    const parsed = safeParseJSON<GeminiDomainVerdict[]>(text);

    if (parsed && Array.isArray(parsed)) {
      const validDecisions = ['SAFE_NECESSARY', 'SAFE_UNNECESSARY', 'SUSPICIOUS', 'MALICIOUS'];
      const verdicts = parsed
        .filter(v => v.domain && validDecisions.includes(v.decision))
        .map(v => ({
          domain: v.domain,
          decision: v.decision,
          confidence: Math.max(0, Math.min(100, v.confidence ?? 50)),
          risk_score: Math.max(0, Math.min(100, v.risk_score ?? 50)),
          reasoning: v.reasoning || 'No reasoning provided',
          signals: {
            known_service: v.signals?.known_service ?? false,
            data_collection_pattern: v.signals?.data_collection_pattern ?? false,
            uses_https: v.signals?.uses_https ?? true,
            suspicious_keywords: v.signals?.suspicious_keywords ?? [],
            ip_based: v.signals?.ip_based ?? false,
          },
        }));

      for (const v of verdicts) {
        const icon = v.decision === 'SAFE_NECESSARY' ? '✅' :
                     v.decision === 'SAFE_UNNECESSARY' ? '🔵' :
                     v.decision === 'SUSPICIOUS' ? '⚠️' : '🔴';
        console.log(`[Gemini] ${icon} ${v.domain} → ${v.decision} (${v.confidence}%)`);
      }

      return verdicts;
    }

    console.warn(`⚠️  Gemini domain analysis returned unparseable response`);
    return [];
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    console.warn(`⚠️  Gemini domain trust analysis failed: ${msg}`);
    return [];
  }
}

// ─── Combined Runner ───────────────────────────────────────────

/**
 * Runs all Gemini analyses if conditions are met.
 * Only fires when 2+ scanners have flagged something.
 *
 * Three API calls:
 *   1. classifyTyposquat() — is this a typosquat/slopsquat?
 *   2. analyzeScript()     — is this script malicious?
 *   3. analyzeDomainTrust() — are detected domains safe or malicious?
 *
 * @param flagCount       - Number of scanners that flagged something
 * @param packageName     - Package name (for typosquat check)
 * @param scriptContent   - Content of flagged script (for analysis)
 * @param networkFindings - Network scanner findings (for domain trust)
 * @param metadata        - Optional package metadata for typosquat context
 */
export async function runGeminiAnalysis(
  flagCount: number,
  packageName: string,
  scriptContent?: string,
  networkFindings?: string[],
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

  // Call 3: Domain trust verification
  if (networkFindings && networkFindings.length > 0) {
    results.domainVerdicts = await analyzeDomainTrust(networkFindings);
  }

  return results;
}
