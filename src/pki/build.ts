import { equalBytes } from './hex';
import { validatePath } from './validate';
import type { BuildOutcome, BuildStep, LabCert, ValidateOptions } from './types';

export interface BuildParams {
  leaf: LabCert;
  /** Intermediates on offer, in presentation order (the order matters to the naive builder). */
  bag: LabCert[];
  validateOpts: ValidateOptions;
  /**
   * false = the naive builder: commit to the FIRST issuer whose signature
   * verifies at every level, validate the single resulting chain once, and on
   * any failure report that chain's error and stop. This is the behavior that
   * made OpenSSL 1.0.2 fail closed on the expired DST Root X3 cross-sign in
   * September 2021 even though a valid path to ISRG Root X1 existed.
   * true = RFC 4158-style depth-first search WITH backtracking: on a rejected
   * candidate path, return to the last choice point and try the next issuer.
   */
  backtrack: boolean;
}

/**
 * Path building is SEARCH over "who could have signed this?"; path validation
 * is the RFC 5280 §6 checklist run on one candidate path. This function keeps
 * the two phases explicit and records every move for the step-through UI.
 * Every 'consider' step performs a real ECDSA verification.
 */
export async function buildAndValidate(params: BuildParams): Promise<BuildOutcome> {
  const { leaf, bag, validateOpts, backtrack } = params;
  const trust = validateOpts.trustStore;
  const steps: BuildStep[] = [];
  let pathsTried = 0;

  const inTrust = (c: LabCert) => trust.some((t) => equalBytes(t.cert.rawData, c.cert.rawData));

  steps.push({
    action: 'start',
    certId: leaf.id,
    pathIds: [leaf.id],
    note: `Start from the leaf "${leaf.nickname}". Goal: a path ending at a trust-store anchor that ` +
      `survives RFC 5280 §6 validation.`,
  });

  // Self-anchored corner case: a path of just the leaf, if the leaf claims to
  // be its own issuer.
  const isSelfSigned = leaf.cert.subject === leaf.cert.issuer;

  async function search(path: LabCert[]): Promise<BuildOutcome | 'exhausted' | 'gave-up'> {
    const top = path[path.length - 1];

    // Candidate issuers: by DN chaining, from the bag first (presentation
    // order), then the trust store. Certs already in the path are skipped to
    // avoid loops.
    const candidates = [...bag, ...trust].filter(
      (c) =>
        c.cert.subject === top.cert.issuer &&
        !path.some((p) => equalBytes(p.cert.rawData, c.cert.rawData)),
    );

    if (candidates.length === 0 && !(isSelfSigned && path.length === 1)) {
      steps.push({
        action: 'dead-end',
        certId: top.id,
        pathIds: path.map((p) => p.id),
        note: `No certificate on offer has subject DN "${top.cert.issuer}" — nothing can extend this branch.`,
      });
      return 'exhausted';
    }

    const tryCandidatePath = async (candidatePath: LabCert[]): Promise<BuildOutcome | 'exhausted' | 'gave-up'> => {
      pathsTried += 1;
      steps.push({
        action: 'validate',
        certId: candidatePath[candidatePath.length - 1].id,
        pathIds: candidatePath.map((p) => p.id),
        note: `Candidate path complete — hand it to the RFC 5280 §6 validator. Building is over; ` +
          `the checklist begins.`,
      });
      const result = await validatePath(candidatePath, validateOpts);
      if (result.verdict === 'ACCEPT') {
        steps.push({
          action: 'path-accepted',
          certId: null,
          pathIds: candidatePath.map((p) => p.id),
          note: `Every check passes. Verdict: ACCEPT.`,
        });
        return { found: true, path: candidatePath, result, steps, pathsTried };
      }
      if (result.verdict === 'UNKNOWN') {
        steps.push({
          action: 'path-indeterminate',
          certId: null,
          pathIds: candidatePath.map((p) => p.id),
          note: `Every evaluated check passes, but at least one required check was not evaluated. Verdict: UNKNOWN.`,
        });
        return { found: true, path: candidatePath, result, steps, pathsTried };
      }
      const why = result.failures[0];
      steps.push({
        action: 'path-rejected',
        certId: why?.certId ?? null,
        pathIds: candidatePath.map((p) => p.id),
        note: `Validator rejects this path — ${why?.label ?? 'a check'} fails. Note the signature chain ` +
          `${result.signatureChainOk ? 'is fully valid' : 'also fails'}: ` +
          (result.signatureChainOk
            ? 'this rejection is pure policy, no cryptography was harmed.'
            : 'even the cryptography disagrees here.'),
      });
      if (!backtrack) {
        steps.push({
          action: 'give-up',
          certId: null,
          pathIds: candidatePath.map((p) => p.id),
          note: `The naive builder gives up: it reports this one chain's error and never returns to try ` +
            `another issuer. The learner sees a failed connection — for a leaf that has a perfectly ` +
            `valid path.`,
        });
        return 'gave-up';
      }
      steps.push({
        action: 'backtrack',
        certId: candidatePath[candidatePath.length - 1].id,
        pathIds: path.map((p) => p.id),
        note: `Backtrack: un-choose the last issuer and try the next candidate.`,
      });
      return 'exhausted';
    };

    // Self-signed leaf may present itself as a complete (one-cert) path.
    if (isSelfSigned && path.length === 1) {
      steps.push({
        action: 'reached-anchor',
        certId: top.id,
        pathIds: path.map((p) => p.id),
        note: `"${top.nickname}" claims to be its own issuer — treat it as a complete one-certificate path.`,
      });
      const r = await tryCandidatePath([...path]);
      if (r !== 'exhausted') return r;
    }

    for (const cand of candidates) {
      steps.push({
        action: 'consider',
        certId: cand.id,
        pathIds: path.map((p) => p.id),
        note: `Consider "${cand.nickname}" as the issuer of "${top.nickname}" (subject DN matches).`,
      });
      const sigOk = await top.cert.verify({ publicKey: cand.cert.publicKey, signatureOnly: true });
      steps.push({
        action: sigOk ? 'link-ok' : 'link-bad',
        certId: cand.id,
        pathIds: [...path, cand].map((p) => p.id),
        note: sigOk
          ? `Real ECDSA verify: the signature on "${top.nickname}" checks out under "${cand.nickname}"'s key.`
          : `Real ECDSA verify: signature does NOT verify under "${cand.nickname}"'s key — discard this link.`,
      });
      if (!sigOk) continue;

      const extended = [...path, cand];
      if (inTrust(cand)) {
        steps.push({
          action: 'reached-anchor',
          certId: cand.id,
          pathIds: extended.map((p) => p.id),
          note: `"${cand.nickname}" is in the trust store — the search phase found a complete candidate path.`,
        });
        const r = await tryCandidatePath(extended);
        if (r !== 'exhausted') return r;
      } else {
        const r = await search(extended);
        if (r !== 'exhausted') return r;
      }
      if (!backtrack) {
        // A naive builder never reconsiders a signature-valid choice.
        return 'gave-up';
      }
    }
    return 'exhausted';
  }

  const outcome = await search([leaf]);
  if (outcome === 'exhausted') {
    steps.push({
      action: 'give-up',
      certId: null,
      pathIds: [leaf.id],
      note: backtrack
        ? `Search exhausted: no path from this leaf to any trust anchor survives validation.`
        : `The naive builder found no chain at all.`,
    });
  }
  if (outcome === 'exhausted' || outcome === 'gave-up') {
    return { found: false, path: null, result: null, steps, pathsTried };
  }
  return outcome;
}
