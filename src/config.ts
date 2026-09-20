import { z } from 'zod';

const schema = z.object({
  PORT: z.coerce.number().int().min(1).max(65535).default(3350),
  ADMIN_TOKEN: z.string().min(16, 'ADMIN_TOKEN must be at least 16 chars'),
  DB_PATH: z.string().default('./data/status.db'),
  ALLOW_PRIVATE_TARGETS: z.enum(['0', '1']).default('0'),
  RUN_CHECKER: z.enum(['0', '1']).default('1'),
});
export type Config = z.infer<typeof schema>;
export const loadConfig = (env: NodeJS.ProcessEnv = process.env): Config => schema.parse(env);

export const PLANS = {
  free: { maxPages: 1, maxMonitors: 5, minIntervalSeconds: 300 },
  pro: { maxPages: 10, maxMonitors: 50, minIntervalSeconds: 60 },
} as const;
export type Plan = keyof typeof PLANS;

/** Consecutive failed checks before an incident opens (avoids one-blip false alarms). */
export const FAILURE_THRESHOLD = 2;
