/**
 * ═══════════════════════════════════════════════════════════
 *  AEGIS-AST — Dependency Comparator
 *  Owner: Person 1 (Core Engine)
 * 
 *  Responsibilities:
 *  - Compare declared dependencies (package.json) vs used (imports)
 *  - Identify PHANTOM dependencies (declared but NOT used)
 *  - Identify MISSING dependencies (used but NOT declared)
 * 
 *  ⚠️ PHANTOM DEPENDENCIES = MALICIOUS SIGNAL
 *     Declared ≠ Used → suspicious
 * ═══════════════════════════════════════════════════════════
 */

import { ComparatorResult, PackageMetadata, ImportScanResult } from '../types';

/**
 * Compares declared dependencies against actually used imports.
 *
 * @param metadata - Parsed package.json with declared dependencies
 * @param imports  - Extracted imports from source code
 * @returns ComparatorResult with phantom, used, and missing deps
 *
 * @example
 * ```ts
 * const result = compareDependencies(metadata, imports);
 * if (result.phantom.length > 0) {
 *   console.warn('🚨 PHANTOM DEPENDENCIES DETECTED:', result.phantom);
 * }
 * ```
 */
export function compareDependencies(
  metadata: PackageMetadata,
  imports: ImportScanResult
): ComparatorResult {
  // 1. Get all declared deps from metadata.dependencies
  const declaredDeps = Object.keys(metadata.dependencies || {});
  // 2. Get all used deps from imports.usedDependencies
  const usedDeps = imports.usedDependencies || [];
  
  // Convert arrays to Sets for O(1) lookup efficiency
  const declaredSet = new Set(declaredDeps);
  const usedSet = new Set(usedDeps);

  // 3. phantom = declared - used
  const phantom = declaredDeps.filter(dep => !usedSet.has(dep));
  // 4. missing = used - declared
  const missing = usedDeps.filter(dep => !declaredSet.has(dep));
  // 5. usedDependencies = declared ∩ used
  const usedDependencies = declaredDeps.filter(dep => usedSet.has(dep));

  return { usedDependencies, phantom, missing };
}
