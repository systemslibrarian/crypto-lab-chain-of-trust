import { beforeAll, describe, expect, it } from 'vitest';
import { generateLabPki } from './certgen';
import { STAGES } from './scenarios';
import { validatePath } from './validate';
import type { LabPki, ValidateOptions } from './types';

let pki: LabPki;
beforeAll(async () => {
  pki = await generateLabPki();
}, 30_000);

function stageOpts(stage: (typeof STAGES)[number]): ValidateOptions {
  return {
    trustStore: stage.trustIds.map((id) => pki.byId(id)),
    host: stage.host,
    requiredEku: stage.requiredEku,
    revoked: new Set(stage.revokedIds),
  };
}

describe('RFC 5280 §6 validator vs every stage of the trap ladder', () => {
  for (const stage of STAGES) {
    describe(`stage ${stage.n}: ${stage.title}`, () => {
      it(`verdict is ${stage.expectedVerdict}`, async () => {
        const path = stage.intendedPathIds.map((id) => pki.byId(id));
        const result = await validatePath(path, stageOpts(stage));
        expect(result.verdict).toBe(stage.expectedVerdict);
      });

      it(`signature chain fact is ${stage.expectedSignatureOk} — independent of the verdict`, async () => {
        const path = stage.intendedPathIds.map((id) => pki.byId(id));
        const result = await validatePath(path, stageOpts(stage));
        expect(result.signatureChainOk).toBe(stage.expectedSignatureOk);
      });

      if (stage.expectedVerdict === 'REJECT') {
        it(`the failing checks are exactly [${stage.culpritChecks.join(', ')}]`, async () => {
          const path = stage.intendedPathIds.map((id) => pki.byId(id));
          const result = await validatePath(path, stageOpts(stage));
          const failedIds = [...new Set(result.failures.map((f) => f.id))].sort();
          expect(failedIds).toEqual([...stage.culpritChecks].sort());
        });
      }
    });
  }

  it('every stage carries learner-facing brief, hint, and lesson text', () => {
    for (const s of STAGES) {
      expect(s.brief.length, s.id).toBeGreaterThan(40);
      expect(s.hint.length, s.id).toBeGreaterThan(40);
      expect(s.lesson.length, s.id).toBeGreaterThan(40);
      // the hint must nudge, not name the failing check outright
      for (const culprit of s.culpritChecks) {
        expect(s.hint.toLowerCase()).not.toContain(culprit);
      }
    }
  });

  it('every REJECT stage in the ladder still has a fully valid signature chain (the thesis of the lab)', () => {
    const rejects = STAGES.filter((s) => s.expectedVerdict === 'REJECT');
    expect(rejects.length).toBe(9);
    expect(rejects.every((s) => s.expectedSignatureOk)).toBe(true);
  });
});

describe('validator invariants', () => {
  it('verdict is ACCEPT exactly when zero checks fail, across every stage path', async () => {
    for (const stage of STAGES) {
      const path = stage.intendedPathIds.map((id) => pki.byId(id));
      const result = await validatePath(path, stageOpts(stage));
      expect(result.verdict === 'ACCEPT', stage.id).toBe(result.failures.length === 0);
      expect(result.failures.every((f) => !f.ok), stage.id).toBe(true);
      // failures is exactly the failing subset of checks
      expect(result.failures.length, stage.id).toBe(result.checks.filter((c) => !c.ok).length);
    }
  });

  it('an empty path is rejected loudly, not validated vacuously', async () => {
    await expect(validatePath([], { trustStore: [pki.byId('root-y')] })).rejects.toThrow(/empty/);
  });

  it('a path with a duplicated certificate fails closed', async () => {
    const leaf = pki.byId('leaf-www');
    const result = await validatePath([leaf, leaf, pki.byId('root-y')], {
      trustStore: [pki.byId('root-y')],
    });
    expect(result.verdict).toBe('REJECT');
  });

  it('the signature-fact chip data can never disagree with the per-link checks', async () => {
    for (const stage of STAGES) {
      const path = stage.intendedPathIds.map((id) => pki.byId(id));
      const result = await validatePath(path, stageOpts(stage));
      const sigChecks = result.checks.filter((c) => c.id === 'signature');
      expect(result.signatureChainOk, stage.id).toBe(sigChecks.every((c) => c.ok));
    }
  });
});

describe('validator details', () => {
  it('exactly the signature checks are marked cryptographic; all others are policy', async () => {
    const stage = STAGES[1]; // ca-false
    const path = stage.intendedPathIds.map((id) => pki.byId(id));
    const result = await validatePath(path, stageOpts(stage));
    for (const c of result.checks) {
      expect(c.cryptographic).toBe(c.id === 'signature');
    }
  });

  it('a truncated path (no anchor reached) fails trust-anchor, not signature', async () => {
    const path = [pki.byId('leaf-www'), pki.byId('issuing-b')]; // stops at the intermediate
    const result = await validatePath(path, {
      trustStore: [pki.byId('root-y')],
      host: 'www.example.test',
      requiredEku: 'serverAuth',
    });
    expect(result.verdict).toBe('REJECT');
    expect(result.failures.map((f) => f.id)).toContain('trust-anchor');
    expect(result.signatureChainOk).toBe(true);
  });

  it('a mis-assembled path (wrong issuer picked) fails the signature check', async () => {
    // Learner wrongly claims Root X vouches for issuing-b.
    const path = [pki.byId('leaf-www'), pki.byId('issuing-b'), pki.byId('root-x')];
    const result = await validatePath(path, { trustStore: [pki.byId('root-x')] });
    expect(result.verdict).toBe('REJECT');
    expect(result.signatureChainOk).toBe(false);
    const sigFailures = result.failures.filter((f) => f.id === 'signature');
    expect(sigFailures.length).toBeGreaterThan(0);
  });

  it('the same path ACCEPTed under Root Y is REJECTed when the trust store is emptied', async () => {
    const path = ['leaf-www', 'issuing-b', 'root-y'].map((id) => pki.byId(id));
    const withY = await validatePath(path, { trustStore: [pki.byId('root-y')] });
    const withoutY = await validatePath(path, { trustStore: [pki.byId('root-x')] });
    expect(withY.verdict).toBe('ACCEPT');
    expect(withoutY.verdict).toBe('REJECT');
    // identical bytes, identical crypto — only the configuration moved
    expect(withY.signatureChainOk).toBe(true);
    expect(withoutY.signatureChainOk).toBe(true);
  });

  it('an unexpired path validated at a future date fails validity (time is an input)', async () => {
    const path = ['leaf-www', 'issuing-b', 'root-y'].map((id) => pki.byId(id));
    const future = new Date(Date.now() + 1000 * 24 * 60 * 60 * 1000);
    const result = await validatePath(path, { trustStore: [pki.byId('root-y')], at: future });
    expect(result.verdict).toBe('REJECT');
    expect(result.failures.map((f) => f.id)).toContain('validity');
    expect(result.signatureChainOk).toBe(true);
  });

  it('EKU absent means unrestricted per RFC 5280 (documented divergence from CABF)', async () => {
    // Roots in this lab have no EKU; build a path where the "leaf" is a root.
    const path = [pki.byId('root-y')];
    const result = await validatePath(path, {
      trustStore: [pki.byId('root-y')],
      requiredEku: 'serverAuth',
    });
    const eku = result.checks.find((c) => c.id === 'eku');
    expect(eku?.ok).toBe(true);
  });
});
