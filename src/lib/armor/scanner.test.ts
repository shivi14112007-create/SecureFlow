import { describe, it, expect, vi, beforeEach } from 'vitest';
import { maskSecrets, extractAddedLines, shouldIgnore, sanitizeRecursively, filterFalsePositives, compileIgnorePatterns } from './scanner';
import type { ScanFinding } from './scanner';

// ─── maskSecrets ──────────────────────────────────────────────────────────────

describe('maskSecrets', () => {
  it('returns empty string for empty input', () => {
    expect(maskSecrets('')).toBe('');
  });

  it('redacts Anthropic API keys', () => {
    const input = 'api key is sk-ant-api03-abcdef1234567890abcdef1234567890 more text';
    expect(maskSecrets(input)).toContain('[REDACTED_BY_THE_PROFESSOR]');
    expect(maskSecrets(input)).not.toContain('sk-ant-api03-');
  });

  it('redacts GitHub PATs (ghp_ format)', () => {
    const input = 'token=ghp_abcdefghijklmnopqrstuvwxyzabcdefghijklm';
    expect(maskSecrets(input)).toContain('[REDACTED_BY_THE_PROFESSOR]');
  });

  it('redacts GitHub PATs (github_pat_ format)', () => {
    const input = 'token=github_pat_11AAABBB111_abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefg';
    expect(maskSecrets(input)).toContain('[REDACTED_BY_THE_PROFESSOR]');
  });

  it('redacts JSON Web Tokens', () => {
    const input = 'jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3j_VN3M5qVZgX5vLQ7zGQ6R8y3Kx9w0c';
    expect(maskSecrets(input)).toContain('[REDACTED_BY_THE_PROFESSOR]');
  });

  it('redacts OpenAI sk- API keys', () => {
    const input = 'key=sk-proj-abcdefghijklmnopqrstuvwxyz1234567890abcdef';
    expect(maskSecrets(input)).toContain('[REDACTED_BY_THE_PROFESSOR]');
  });

  it('redacts Stripe API keys', () => {
    // Stripe key pattern: sk_live_ prefix — value split to avoid secret scanning
    const prefix = 'sk_li' + 've_';
    const input = `stripe=${prefix}XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`;
    expect(maskSecrets(input)).toContain('[REDACTED_BY_THE_PROFESSOR]');
  });

  it('redacts Slack tokens', () => {
    // Slack token pattern: xoxb- prefix — value split to avoid secret scanning
    const prefix = 'xox' + 'b-';
    const input = `slack=${prefix}0000000000-XXXXXXXXXXXXXXXXXXXXXXXX`;
    expect(maskSecrets(input)).toContain('[REDACTED_BY_THE_PROFESSOR]');
  });

  it('redacts AWS access keys', () => {
    const input = 'aws=AKIAIOSFODNN7EXAMPLE';
    expect(maskSecrets(input)).toContain('[REDACTED_BY_THE_PROFESSOR]');
  });

  it('redacts database passwords in connection URIs', () => {
    const input = 'mongodb://user:supersecret@localhost:27017/mydb';
    expect(maskSecrets(input)).toContain('[REDACTED_BY_THE_PROFESSOR]');
    expect(maskSecrets(input)).toContain('mongodb://user:');
    expect(maskSecrets(input)).not.toContain('supersecret');
  });

  it('returns non-secret text unchanged', () => {
    const text = 'const x = 42; // normal comment';
    expect(maskSecrets(text)).toBe(text);
  });
});

// ─── extractAddedLines ───────────────────────────────────────────────────────

describe('extractAddedLines', () => {
  it('returns empty string for empty input', () => {
    expect(extractAddedLines('')).toBe('');
  });

  it('extracts lines starting with + and tags them [ADDED]', () => {
    const patch = [
      '--- a/src/db.ts',
      '+++ b/src/db.ts',
      '@@ -1,3 +1,4 @@',
      ' const x = 1;',
      ' const y = 2;',
      '+const z = 3;',
      '+const secret = "sk-live-abc";',
      ' const w = 4;',
    ].join('\n');

    const result = extractAddedLines(patch);
    expect(result).toContain('[ADDED] const z = 3;');
    expect(result).toContain('[ADDED] const secret = "sk-live-abc";');
    // Context lines should be included without [ADDED] tag
    expect(result).toContain('const x = 1;');
  });

  it('filters out ---, +++, and @@ header lines', () => {
    const patch = [
      '--- a/file.ts',
      '+++ b/file.ts',
      '@@ -0,0 +1 @@',
      '+new line',
    ].join('\n');

    const result = extractAddedLines(patch);
    expect(result).not.toContain('---');
    expect(result).not.toContain('+++');
    expect(result).not.toContain('@@');
    expect(result).toContain('[ADDED] new line');
  });

  it('preserves context lines without [ADDED] tag', () => {
    const patch = [
      ' unchanged',
      '+added',
    ].join('\n');

    const result = extractAddedLines(patch);
    expect(result).toContain('unchanged');
    expect(result).toContain('[ADDED] added');
  });
});

// ─── shouldIgnore ─────────────────────────────────────────────────────────────

describe('shouldIgnore', () => {
  it('ignores files in dist/ directory', () => {
    expect(shouldIgnore('dist/output.js')).toBe(true);
  });

  it('ignores files in node_modules/', () => {
    expect(shouldIgnore('node_modules/package/index.js')).toBe(true);
  });

  it('ignores files with .md extension', () => {
    expect(shouldIgnore('README.md')).toBe(true);
  });

  it('ignores .lock files', () => {
    expect(shouldIgnore('package-lock.json')).toBe(true);
  });

  it('does NOT ignore .env.example files', () => {
    expect(shouldIgnore('.env.example')).toBe(false);
  });

  it('ignores package.json', () => {
    expect(shouldIgnore('package.json')).toBe(true);
  });

  it('ignores .gitignore', () => {
    expect(shouldIgnore('.gitignore')).toBe(true);
  });

  it('uses custom ignore patterns', () => {
    const customPatterns = compileIgnorePatterns(['custom-dir/']);
    expect(shouldIgnore('custom-dir/some-file.ts', customPatterns)).toBe(true);
  });

  it('does not ignore regular source files', () => {
    expect(shouldIgnore('src/app.ts')).toBe(false);
    expect(shouldIgnore('src/components/Button.tsx')).toBe(false);
  });
});

// ─── sanitizeRecursively ──────────────────────────────────────────────────────

describe('sanitizeRecursively', () => {
  it('decodes HTML entities', () => {
    expect(sanitizeRecursively('<script>alert(1)</script>')).toBe('<script>alert(1)</script>');
  });

  it('removes zero-width characters', () => {
    const input = 'hello\u200Bworld\u200Ctest';
    expect(sanitizeRecursively(input)).toBe('helloworldtest');
  });

  it('handles nested encoding recursively', () => {
    const input = '&lt;script>';
    const result = sanitizeRecursively(input);
    expect(result).not.toContain('&lt;');
  });

  it('truncates at MAX_SANITIZED_LENGTH (100k)', () => {
    const long = 'x'.repeat(150000);
    expect(sanitizeRecursively(long).length).toBe(100000);
  });

  it('returns unchanged input when no decoding needed', () => {
    const text = 'const x = "hello world";';
    expect(sanitizeRecursively(text)).toBe(text);
  });
});

// ─── filterFalsePositives ─────────────────────────────────────────────────────

describe('filterFalsePositives', () => {
  const makeFinding = (overrides: Partial<ScanFinding> = {}): ScanFinding => ({
    type: 'Secret',
    severity: 'HIGH',
    description: 'API key found',
    fileLocation: 'src/file.ts',
    codeSnippet: 'const key = "sk-live-abc123"',
    ...overrides,
  });

  it('removes findings in .env.example files with placeholder values', () => {
    const findings = [makeFinding({
      fileLocation: '.env.example',
      codeSnippet: 'API_KEY=your_actual_key_here',
    })];
    expect(filterFalsePositives(findings)).toHaveLength(0);
  });

  it('removes findings in .env.example files with empty values', () => {
    const findings = [makeFinding({
      fileLocation: '.env.example',
      codeSnippet: 'API_KEY=""',
    })];
    expect(filterFalsePositives(findings)).toHaveLength(0);
  });

  it('retains findings in .env.example with real-looking high-entropy credentials', () => {
    const findings = [makeFinding({
      fileLocation: '.env.example',
      codeSnippet: 'API_KEY=sk-live-abcdefghijklmnopqrstuvwxyz1234567890',
    })];
    expect(filterFalsePositives(findings)).toHaveLength(1);
  });

  it('removes findings in seed.ts with placeholder values', () => {
    const findings = [makeFinding({
      fileLocation: 'prisma/seed.ts',
      codeSnippet: 'description: "your_description_here"',
    })];
    expect(filterFalsePositives(findings)).toHaveLength(0);
  });

  it('removes false logic flaws in schema.prisma', () => {
    const findings = [makeFinding({
      type: 'Vulnerability',
      fileLocation: 'prisma/schema.prisma',
      codeSnippet: 'id Int @id',
      description: 'Int type used',
    })];
    expect(filterFalsePositives(findings)).toHaveLength(0);
  });

  it('retains real findings in non-special files', () => {
    const findings = [makeFinding({
      fileLocation: 'src/api/route.ts',
      codeSnippet: 'console.log(process.env.API_KEY)',
    })];
    expect(filterFalsePositives(findings)).toHaveLength(1);
  });
});

// ─── compileIgnorePatterns ────────────────────────────────────────────────────

describe('compileIgnorePatterns', () => {
  it('compiles simple directory patterns', () => {
    const patterns = compileIgnorePatterns(['vendor/', 'tmp/']);
    expect(patterns).toHaveLength(2);
    expect(patterns[0].test('vendor/lib.js')).toBe(true);
    expect(patterns[1].test('tmp/cache.dat')).toBe(true);
  });

  it('filters out empty and comment lines', () => {
    const patterns = compileIgnorePatterns(['', '# comment', 'src/']);
    expect(patterns).toHaveLength(1);
  });
});