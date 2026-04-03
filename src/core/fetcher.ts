/**
 * ═══════════════════════════════════════════════════════════
 *  AEGIS-AST — Package Fetcher
 *  Owner: Person 1 (Core Engine)
 * 
 *  Responsibilities:
 *  - Download package tarball from npm registry
 *  - Extract to /tmp/aegis/<package-name>
 *  - Parse and return package.json metadata
 * ═══════════════════════════════════════════════════════════
 */

import { FetchResult, PackageMetadata } from '../types';
import * as fs from 'fs';
import * as fsp from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

/**
 * Fetches a package from the npm registry, downloads the tarball,
 * and extracts it to a temporary directory.
 *
 * @param packageName - Name of the npm package (e.g., "axios")
 * @param version - Specific version or "latest"
 * @returns FetchResult with extractedPath and metadata
 *
 * @example
 * ```ts
 * const result = await fetchPackage("axios", "latest");
 * console.log(result.extractedPath);  // /tmp/aegis/axios
 * console.log(result.metadata.dependencies);
 * ```
 */
export async function fetchPackage(
  packageName: string,
  version: string = 'latest'
): Promise<FetchResult> {
const registryUrl = process.env.NPM_REGISTRY_URL || 'https://registry.npmjs.org';
const packageUrl = `${registryUrl}/${packageName}/${version}`;

  try {
    // 1. GET package metadata from registry
    const res = await fetch(packageUrl);
    if (!res.ok) {
      throw new Error(`Failed to fetch metadata for ${packageName}@${version}: ${res.statusText}`);
    }
    const data = (await res.json()) as { dist?: { tarball?: string } };

    // 2. Extract tarball URL
    const tarballUrl = data.dist?.tarball;
    if (!tarballUrl) {
      throw new Error(`No tarball URL found for ${packageName}@${version}`);
    }

    // Prepare temp directories
    const tmpBase = path.join(os.tmpdir(), 'aegis');
    const extractPath = path.join(tmpBase, packageName);
    const tarballPath = path.join(tmpBase, `${packageName.replace(/\//g, '-')}.tgz`);

    await fsp.mkdir(extractPath, { recursive: true });

    // 3. Download tarball
    const tarRes = await fetch(tarballUrl);
    if (!tarRes.ok) {
      throw new Error(`Failed to download tarball: ${tarRes.statusText}`);
    }
    const arrayBuffer = await tarRes.arrayBuffer();
    await fsp.writeFile(tarballPath, Buffer.from(arrayBuffer));

    // 4. Extract tarball
    // Note: NPM tarballs always wrap their contents in a 'package/' directory.
    // We use --strip-components=1 to dump the files directly into our target folder.
    await execAsync(`tar -xzf ${tarballPath} -C ${extractPath} --strip-components=1`);

    // Clean up the raw .tgz file now that we've extracted it
    await fsp.rm(tarballPath, { force: true });

    // 5. Parse package.json
    const metadata = parsePackageJson(extractPath);

    // 6. Return FetchResult
    return {
      extractedPath: extractPath,
      metadata
    };
  } catch (error) {
    throw new Error(`Fetcher Error [${packageName}]: ${(error as Error).message}`);
  }
}

/**
 * Parses package.json from an extracted package directory.
 */
export function parsePackageJson(extractedPath: string): PackageMetadata {
  const pkgPath = path.join(extractedPath, 'package.json');
  
  if (!fs.existsSync(pkgPath)) {
    throw new Error(`package.json not found at ${pkgPath}`);
  }

  const fileContent = fs.readFileSync(pkgPath, 'utf-8');
  
  try {
    return JSON.parse(fileContent) as PackageMetadata;
  } catch (error) {
    throw new Error(`Failed to parse package.json at ${pkgPath}`);
  }
}

/**
 * Cleans up the temporary extraction directory.
 */
export async function cleanup(extractedPath: string): Promise<void> {
  try {
    await fsp.rm(extractedPath, { recursive: true, force: true });
  } catch (error) {
    console.error(`Cleanup failed for ${extractedPath}:`, error);
  }
}
