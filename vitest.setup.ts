import { vi } from 'vitest';

// Stub @/lib/prisma so tests never open a real DB connection.
vi.mock('@/lib/prisma', () => ({
  default: {
    user: { count: vi.fn(), findUnique: vi.fn(), create: vi.fn() },
    pullRequest: { count: vi.fn(), findUnique: vi.fn() },
    auditLog: { count: vi.fn() },
    scanResult: { aggregate: vi.fn() },
    repository: { findUnique: vi.fn() },
    finding: { findFirst: vi.fn(), update: vi.fn() },
    webhookEvent: { findUnique: vi.fn(async () => null), create: vi.fn(async () => ({})) },
  },
}));

// Stub groq-sdk globally so every test file gets a consistent mock.
// scanner.ts references Groq.APIConnectionTimeoutError as a static property;
// the mock must expose it or the module-level code throws before any test runs.
vi.mock('groq-sdk', () => {
  class APIConnectionTimeoutError extends Error {
    constructor() { super('timeout'); this.name = 'APIConnectionTimeoutError'; }
  }

  const mockCreate = vi.fn().mockResolvedValue({
    choices: [{ message: { content: JSON.stringify({ findings: [] }) } }],
  });

  class MockGroq {
    static APIConnectionTimeoutError = APIConnectionTimeoutError;
    static mockCreate = mockCreate;
    chat = { completions: { create: mockCreate } };
    constructor(_opts?: unknown) {}
  }

  return { default: MockGroq };
});

// Stub ioredis so tests that import redis.ts don't try to open a real connection.
vi.mock('ioredis', () => {
  class Redis {
    incr = vi.fn(async () => 1);
    expire = vi.fn(async () => 1);
    on = vi.fn();
  }
  return { default: Redis };
});

// Stub next-auth so importing @/auth never tries to read next.config.js.
vi.mock('next-auth', () => ({
  default: vi.fn(() => ({
    handlers: {},
    signIn: vi.fn(),
    signOut: vi.fn(),
    auth: vi.fn(async () => null),
  })),
}));

// Stub @/auth directly so test files that import it get a simple mock.
vi.mock('@/auth', () => ({
  auth: vi.fn(async () => null),
  signIn: vi.fn(),
  signOut: vi.fn(),
}));

// Stub @auth/prisma-adapter to avoid next-auth internals.
vi.mock('@auth/prisma-adapter', () => ({
  PrismaAdapter: vi.fn(() => ({})),
}));
