import { calculateFullRisk, FullScanInput } from '../src/core/risk_engine';
import { extractImports } from '../src/core/imports';
import { walkSourceFiles } from '../src/utils/file_walker';

jest.mock('../src/utils/file_walker', () => ({
  walkSourceFiles: jest.fn(),
  isCommentLine: jest.fn(),
  isMinifiedFile: jest.fn(),
  SOURCE_EXTENSIONS: new Set(['.js', '.ts'])
}));

describe('Aegis-AST: Edge Cases Verification', () => {
  it('should successfully ALLOW a zero-dependency package', () => {
    const input: FullScanInput = {
      packageName: 'zero-dep-util',
      packageVersion: '1.0.0',
      phantomDeps: [], // Empty dependencies
      scannerOutput: {
        scripts: [],
        network: [],
        fs: [],
        exec: [],
        eval: [],
        entropy: []
      }
    };
    
    const result = calculateFullRisk(input);
    expect(result.total).toBe(0);
    expect(result.breakdown.phantom).toBe(0);
  });

  it('should handle pure TypeScript codebase without crashing', () => {
    // Simulated parser output of parsing TS files securely
    const input: FullScanInput = {
      packageName: 'pure-ts-lib',
      packageVersion: '2.4.1',
      phantomDeps: [], 
      scannerOutput: {
        scripts: [],
        network: ['https://example.com/api (TS comment)'],
        fs: [],
        exec: [],
        eval: [],
        entropy: []
      }
    };
    
    const result = calculateFullRisk(input);
    expect(result.total).toBe(25); // Network +25 (ALLOW)
    expect(result.breakdown.phantom).toBe(0);
  });

  it('should handle large scanner output arrays without arithmetic overflow', () => {
    // Generate an artificially inflated scanner output 
    // to prove the risk engine arithmetic arrays do not stack overflow.
    const massiveNetworkArray = Array.from({ length: 5000 }, (_, i) => `url-${i}.com`);
    
    const input: FullScanInput = {
      packageName: 'massive-monolith',
      packageVersion: '9.9.9',
      phantomDeps: ['old-forgotten-dep'], // 1 phantom
      scannerOutput: {
        scripts: [],
        network: massiveNetworkArray,
        fs: [],
        exec: [],
        eval: [],
        entropy: []
      }
    };
    
    const result = calculateFullRisk(input);
    
    // Scoring limits check: finding massive amounts doesn't break arithmetic.
    // Phantom +50, Network +25 => 75 (BLOCK)
    expect(result.total).toBe(75);
    expect(result.breakdown.phantom).toBe(50);
    expect(result.breakdown.network).toBe(25);
  });

  it('should parse TypeScript source with generics and decorators without crashing', async () => {
    const tsSource = `
import { Injectable } from '@nestjs/common';
import axios from 'axios';

@Injectable()
export class UserService<T extends Record<string, unknown>> {
  async fetchUser(id: string): Promise<T> {
    const response = await axios.get<T>(\`/users/\${id}\`);
    return response.data as T;
  }
}
`;

    // Mock walkSourceFiles to return our raw string, simulating P1's fs operations
    (walkSourceFiles as jest.Mock).mockReturnValue([{
      absolutePath: '/fake/path/test.ts',
      relativePath: 'test.ts',
      content: tsSource
    }]);

    // Feed it directly into Babel AST parser (via P1's extractImports wrapper)
    const result = await extractImports('/fake/path');
    
    // Assert parser does not throw and effectively extracts normalized dependencies
    expect(result.usedDependencies).toContain('@nestjs/common');
    expect(result.usedDependencies).toContain('axios');
  });
});
