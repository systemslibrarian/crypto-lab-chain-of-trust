import type * as x509 from '@peculiar/x509';

/**
 * One certificate in the lab PKI. `cert` is a real, DER-encoded X.509
 * certificate carrying a real ECDSA P-256 signature. `id` is a stable lab
 * handle used by scenarios and the revocation fixture.
 */
export interface LabCert {
  id: string;
  nickname: string;
  /** Short role tag for the UI, e.g. "root", "intermediate", "leaf". */
  role: 'root' | 'intermediate' | 'leaf';
  cert: x509.X509Certificate;
}

/** The full generated lab PKI, keyed by lab id. */
export interface LabPki {
  all: LabCert[];
  byId(id: string): LabCert;
}

/**
 * The RFC 5280 §6 checks this lab implements. Exactly one of them
 * ('signature') is cryptographic; every other check is a policy/authority
 * constraint that no signature can satisfy.
 */
export type CheckId =
  | 'trust-anchor'
  | 'signature'
  | 'validity'
  | 'basic-constraints'
  | 'path-len'
  | 'key-usage'
  | 'name-constraints'
  | 'eku'
  | 'revocation'
  | 'hostname';

export interface CheckResult {
  id: CheckId;
  label: string;
  /** Lab id of the certificate the result is attributed to (null = whole path). */
  certId: string | null;
  ok: boolean;
  /** True only for signature checks — the one thing ECDSA can answer. */
  cryptographic: boolean;
  detail: string;
  /** Spec citation, e.g. "RFC 5280 §6.1.4(k)". */
  rfc: string;
}

export interface ValidateOptions {
  /** Trust anchors. Matching is by exact DER byte equality. */
  trustStore: LabCert[];
  /** Validation time; defaults to now. */
  at?: Date;
  /** If set, run the RFC 6125/9525 server-identity check on the leaf. */
  host?: string | null;
  /** Required extended key usage for the leaf, if any. */
  requiredEku?: 'serverAuth' | 'clientAuth' | null;
  /**
   * Revocation statuses, keyed by lab cert id. This is a LOCAL FIXTURE:
   * the lab performs no CRL/OCSP network fetch. The teaching point is that
   * revocation is an input to validation, not a property of the signature.
   */
  revoked?: ReadonlySet<string>;
  /**
   * 'fixture' (default): statuses come from the lab fixture above.
   * 'not-evaluated': no status source exists (imported chains) — the check
   * reports honestly that it was NOT evaluated rather than claiming a pass.
   */
  revocationSource?: 'fixture' | 'not-evaluated';
}

export interface ValidationResult {
  checks: CheckResult[];
  /**
   * The pure-crypto fact, computed independently of the verdict: does every
   * certificate in the presented path carry a signature that verifies under
   * the key of the certificate above it (and the anchor under its own key)?
   */
  signatureChainOk: boolean;
  /** The RFC 5280 verdict: ACCEPT only if every check passed. */
  verdict: 'ACCEPT' | 'REJECT';
  failures: CheckResult[];
}

/** One step of a path-builder run, for the step-through animation. */
export interface BuildStep {
  action:
    | 'start'
    | 'consider'
    | 'link-ok'
    | 'link-bad'
    | 'reached-anchor'
    | 'validate'
    | 'path-rejected'
    | 'path-accepted'
    | 'backtrack'
    | 'dead-end'
    | 'give-up';
  certId: string | null;
  /** Path under construction (leaf first) at this step. */
  pathIds: string[];
  note: string;
}

export interface BuildOutcome {
  found: boolean;
  path: LabCert[] | null;
  result: ValidationResult | null;
  steps: BuildStep[];
  /** Number of complete candidate paths handed to the validator. */
  pathsTried: number;
}
