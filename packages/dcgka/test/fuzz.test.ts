/**
 * Simulation fuzz — the Phase 2 quality gate. Runs the seeded harness
 * (test/sim.ts) across many schedules and asserts convergence, app delivery,
 * and bounded buffers. Any failure names its seed for exact reproduction.
 */

import { describe, expect, it } from 'vitest';
import { runSim, type SimOptions } from './sim.js';
import { MAX_BUFFERED_TOTAL } from '../src/ordering.js';

function assertConverged(seed: number, opt: SimOptions): void {
  const { stats, liveHashes, liveMembers, appDelivered } = runSim(seed, opt);

  // 1. All live members agree on the tree hash (Spike B §9: identical filtered-tree hashes).
  const hashes = [...liveHashes.values()];
  const memberCounts = [...liveMembers.values()];
  const distinctHashes = new Set(hashes);
  expect(distinctHashes.size, `seed ${seed}: tree hashes diverged across ${hashes.length} live clients`).toBe(1);

  // 2. All live members agree on the membership size.
  expect(new Set(memberCounts).size, `seed ${seed}: member counts diverged (${memberCounts.join(',')})`).toBe(1);

  // 3. End-to-end app delivery after the settling update.
  expect(appDelivered.got, `seed ${seed}: only ${appDelivered.got}/${appDelivered.expected} received the final app`).toBe(
    appDelivered.expected,
  );

  // 4. Buffers stayed within the DoS bound.
  expect(stats.maxBuffered, `seed ${seed}: buffer exceeded bound`).toBeLessThanOrEqual(MAX_BUFFERED_TOTAL);

  // 5. The fuzz actually exercised the protocol (not a degenerate run).
  expect(stats.updates + stats.apps, `seed ${seed}: degenerate run`).toBeGreaterThan(0);
  expect(stats.finalMembers, `seed ${seed}: group collapsed`).toBeGreaterThanOrEqual(2);
}

const BASE: SimOptions = {
  founding: 3,
  poolSize: 7,
  steps: 400,
  lossProb: 0.15,
  dupProb: 0.08,
  offlineProb: 0.4,
  maxGroup: 6,
};

describe('simulation fuzz (Phase 2 quality gate)', () => {
  it('converges across 12 seeded schedules (lossy/reorder/dup/partition + churn)', () => {
    for (let seed = 1; seed <= 12; seed++) {
      assertConverged(seed, BASE);
    }
  });

  it('static membership, heavy loss + reordering (no churn)', () => {
    const opt: SimOptions = { ...BASE, poolSize: 4, founding: 4, maxGroup: 4, lossProb: 0.3, dupProb: 0.15, steps: 400 };
    for (let seed = 100; seed <= 106; seed++) {
      assertConverged(seed, opt);
    }
  });

  it('add/remove churn dominant, small groups', () => {
    const opt: SimOptions = { ...BASE, founding: 2, poolSize: 8, maxGroup: 6, steps: 400, offlineProb: 0.25 };
    for (let seed = 200; seed <= 207; seed++) {
      assertConverged(seed, opt);
    }
  });

  it('long run, larger group', () => {
    const opt: SimOptions = { ...BASE, founding: 4, poolSize: 9, maxGroup: 8, steps: 700 };
    for (const seed of [7777, 9999]) {
      assertConverged(seed, opt);
    }
  });
});
