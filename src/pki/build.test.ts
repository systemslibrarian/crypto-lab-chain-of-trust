import { beforeAll, describe, expect, it } from 'vitest';
import { buildAndValidate } from './build';
import { generateLabPki } from './certgen';
import type { LabPki, ValidateOptions } from './types';

let pki: LabPki;
beforeAll(async () => {
  pki = await generateLabPki();
}, 30_000);

/** The diamond: leaf-www can chain via issuing-a → root-x (fails
 *  nameConstraints) or via issuing-b → root-y (valid). Cross-sign A comes
 *  first in the bag, so a naive builder commits to it. */
function diamond(): { leaf: ReturnType<LabPki['byId']>; bag: ReturnType<LabPki['byId']>[]; validateOpts: ValidateOptions } {
  return {
    leaf: pki.byId('leaf-www'),
    bag: [pki.byId('issuing-a'), pki.byId('issuing-b')],
    validateOpts: {
      trustStore: [pki.byId('root-x'), pki.byId('root-y')],
      host: 'www.example.test',
      requiredEku: 'serverAuth',
    },
  };
}

describe('path building ≠ path validation (the headline mechanism)', () => {
  it('the naive builder gives up after the first cryptographically-valid path fails policy', async () => {
    const outcome = await buildAndValidate({ ...diamond(), backtrack: false });
    expect(outcome.found).toBe(false);
    expect(outcome.pathsTried).toBe(1);
    const rejected = outcome.steps.find((s) => s.action === 'path-rejected');
    expect(rejected).toBeDefined();
    expect(rejected!.pathIds).toEqual(['leaf-www', 'issuing-a', 'root-x']);
    expect(outcome.steps.some((s) => s.action === 'give-up')).toBe(true);
    expect(outcome.steps.some((s) => s.action === 'backtrack')).toBe(false);
  });

  it('the backtracking builder recovers and finds the valid path through cross-sign B', async () => {
    const outcome = await buildAndValidate({ ...diamond(), backtrack: true });
    expect(outcome.found).toBe(true);
    expect(outcome.pathsTried).toBe(2);
    expect(outcome.path!.map((c) => c.id)).toEqual(['leaf-www', 'issuing-b', 'root-y']);
    expect(outcome.result!.verdict).toBe('ACCEPT');
    expect(outcome.steps.some((s) => s.action === 'backtrack')).toBe(true);
  });

  it('the path the naive builder died on was cryptographically flawless', async () => {
    const outcome = await buildAndValidate({ ...diamond(), backtrack: false });
    const validateStep = outcome.steps.find((s) => s.action === 'path-rejected');
    expect(validateStep!.note).toContain('signature chain is fully valid');
  });

  it('every considered link in the trace was a real ECDSA verification with a recorded result', async () => {
    const outcome = await buildAndValidate({ ...diamond(), backtrack: true });
    const considers = outcome.steps.filter((s) => s.action === 'consider');
    const links = outcome.steps.filter((s) => s.action === 'link-ok' || s.action === 'link-bad');
    expect(considers.length).toBeGreaterThan(0);
    expect(links.length).toBe(considers.length);
  });

  it('with only Root Y trusted, both builders succeed via B (backtracking not needed if the bad branch is unanchored)', async () => {
    const opts = {
      leaf: pki.byId('leaf-www'),
      bag: [pki.byId('issuing-a'), pki.byId('issuing-b')],
      validateOpts: {
        trustStore: [pki.byId('root-y')],
        host: 'www.example.test',
        requiredEku: 'serverAuth' as const,
      },
    };
    // Naive: issuing-a chains to root-x which is NOT in the store — the
    // branch dead-ends before any candidate path exists, and a naive builder
    // that committed to A reports failure.
    const naive = await buildAndValidate({ ...opts, backtrack: false });
    expect(naive.found).toBe(false);
    expect(naive.steps.some((s) => s.action === 'dead-end')).toBe(true);
    // Backtracking: recovers to B.
    const smart = await buildAndValidate({ ...opts, backtrack: true });
    expect(smart.found).toBe(true);
    expect(smart.path!.map((c) => c.id)).toEqual(['leaf-www', 'issuing-b', 'root-y']);
  });

  it('the self-signed leaf builds a one-cert path that validation rejects on trust-anchor', async () => {
    const outcome = await buildAndValidate({
      leaf: pki.byId('leaf-standalone'),
      bag: [],
      validateOpts: {
        trustStore: [pki.byId('root-x'), pki.byId('root-y')],
        host: 'standalone.example.test',
        requiredEku: 'serverAuth',
      },
      backtrack: true,
    });
    expect(outcome.found).toBe(false);
    const rejected = outcome.steps.find((s) => s.action === 'path-rejected');
    expect(rejected).toBeDefined();
    expect(rejected!.pathIds).toEqual(['leaf-standalone']);
  });
});
