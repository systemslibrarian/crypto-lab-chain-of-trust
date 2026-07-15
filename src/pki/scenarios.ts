import type { CheckId } from './types';

/**
 * One puzzle stage. The learner is the validator: they get the leaf, a bag of
 * intermediates, and a trust store; they assemble a path and rule ACCEPT or
 * REJECT (naming the failing check). The stage is graded against the real
 * RFC 5280 §6 implementation in validate.ts — never against these fields.
 * `expected*` below exist only so tests can pin the validator's behavior and
 * so the UI can tell the learner which check they missed.
 */
export interface Stage {
  id: string;
  n: number;
  title: string;
  brief: string;
  leafId: string;
  bagIds: string[];
  trustIds: string[];
  host: string | null;
  requiredEku: 'serverAuth' | 'clientAuth' | null;
  revokedIds: string[];
  expectedVerdict: 'ACCEPT' | 'REJECT';
  /** Checks that fail — naming any of them counts as the right reason. */
  culpritChecks: CheckId[];
  /** Is the signature chain of the intended path cryptographically valid? */
  expectedSignatureOk: boolean;
  /** The intended path (leaf first) tests pin the validator against. */
  intendedPathIds: string[];
  lesson: string;
}

export const STAGES: Stage[] = [
  {
    id: 'baseline',
    n: 1,
    title: 'A valid chain',
    brief:
      'You are connecting to www.example.test. The server presents its leaf plus one intermediate. ' +
      'Your trust store holds Root Y. Build the path and rule.',
    leafId: 'leaf-www',
    bagIds: ['issuing-b'],
    trustIds: ['root-y'],
    host: 'www.example.test',
    requiredEku: 'serverAuth',
    revokedIds: [],
    expectedVerdict: 'ACCEPT',
    culpritChecks: [],
    expectedSignatureOk: true,
    intendedPathIds: ['leaf-www', 'issuing-b', 'root-y'],
    lesson:
      'The baseline: signatures verify AND every constraint holds. Keep this stage in mind — every ' +
      'later stage has the same valid signatures and a different verdict.',
  },
  {
    id: 'ca-false',
    n: 2,
    title: 'The classic: CA:FALSE',
    brief:
      'rogue.example.test presents a chain through "Server Ops" — an ordinary end-entity certificate ' +
      '(basicConstraints CA:FALSE) whose key was used to sign the leaf. Every signature is genuine.',
    leafId: 'leaf-rogue',
    bagIds: ['int-serverops', 'issuing-b'],
    trustIds: ['root-y'],
    host: 'rogue.example.test',
    requiredEku: 'serverAuth',
    revokedIds: [],
    expectedVerdict: 'REJECT',
    culpritChecks: ['basic-constraints', 'key-usage'],
    expectedSignatureOk: true,
    intendedPathIds: ['leaf-rogue', 'int-serverops', 'issuing-b', 'root-y'],
    lesson:
      'A valid signature proves the Server Ops key signed the leaf. It cannot prove Server Ops was ' +
      'ALLOWED to. CA:FALSE (and the missing keyCertSign bit) is where authority lives — verifiers that ' +
      'skipped this check accepted any website’s certificate as a CA. That bug shipped, notably as ' +
      'Apple iOS CVE-2011-0228.',
  },
  {
    id: 'path-len',
    n: 3,
    title: 'Depth budget: pathLenConstraint',
    brief:
      'deep.example.test chains through Deep CA, which was signed by Constrained CA — a CA that Root Y ' +
      'authorized with pathLenConstraint=0: it may sign leaves, but no further CAs.',
    leafId: 'leaf-deep',
    bagIds: ['int-deep', 'int-constrained'],
    trustIds: ['root-y'],
    host: 'deep.example.test',
    requiredEku: 'serverAuth',
    revokedIds: [],
    expectedVerdict: 'REJECT',
    culpritChecks: ['path-len'],
    expectedSignatureOk: true,
    intendedPathIds: ['leaf-deep', 'int-deep', 'int-constrained', 'root-y'],
    lesson:
      'pathLenConstraint is a delegation budget: "you may certify, but you may not mint further ' +
      'certifiers below this depth." Constrained CA’s signature on Deep CA is real ECDSA; the budget it ' +
      'was given is what the extra level exceeds.',
  },
  {
    id: 'expired-int',
    n: 4,
    title: 'Expired intermediate, fresh leaf',
    brief:
      'archive.example.test is comfortably within its own validity dates. The intermediate that signed ' +
      'it expired a month ago.',
    leafId: 'leaf-archive',
    bagIds: ['int-expired'],
    trustIds: ['root-y'],
    host: 'archive.example.test',
    requiredEku: 'serverAuth',
    revokedIds: [],
    expectedVerdict: 'REJECT',
    culpritChecks: ['validity'],
    expectedSignatureOk: true,
    intendedPathIds: ['leaf-archive', 'int-expired', 'root-y'],
    lesson:
      'Expiry does not rot the mathematics — the expired CA’s signature verifies today exactly as it did ' +
      'last year. What lapsed is the issuer’s CLAIM. Every certificate in the path must be in date, not ' +
      'just the leaf. (An expired cert higher up is precisely what broke millions of clients when DST ' +
      'Root X3 expired in September 2021.)',
  },
  {
    id: 'hostname',
    n: 5,
    title: 'Hostname: SAN governs, CN lies',
    brief:
      'You are connecting to www.example.test. The presented leaf’s subject CN says "www.example.test" — ' +
      'but its SAN lists only shop.example.test. The chain to Root Y is flawless.',
    leafId: 'leaf-shop',
    bagIds: ['issuing-b'],
    trustIds: ['root-y'],
    host: 'www.example.test',
    requiredEku: 'serverAuth',
    revokedIds: [],
    expectedVerdict: 'REJECT',
    culpritChecks: ['hostname'],
    expectedSignatureOk: true,
    intendedPathIds: ['leaf-shop', 'issuing-b', 'root-y'],
    lesson:
      'Server identity lives in the SAN extension. The CN is a free-text relic: RFC 6125 only ever ' +
      'allowed it when no SAN dNSName exists, and RFC 9525 and every modern browser ignore it entirely. ' +
      'A verifier with the deprecated CN fallback would have accepted this certificate for the wrong host.',
  },
  {
    id: 'name-constraints',
    n: 6,
    title: 'nameConstraints: outside the territory',
    brief:
      'Same leaf as stage 1 — www.example.test. But this client only trusts Root X, and Root X ' +
      'cross-signed the Issuing CA with nameConstraints permitting only *.internal.test.',
    leafId: 'leaf-www',
    bagIds: ['issuing-a'],
    trustIds: ['root-x'],
    host: 'www.example.test',
    requiredEku: 'serverAuth',
    revokedIds: [],
    expectedVerdict: 'REJECT',
    culpritChecks: ['name-constraints'],
    expectedSignatureOk: true,
    intendedPathIds: ['leaf-www', 'issuing-a', 'root-x'],
    lesson:
      'The identical leaf was ACCEPTED in stage 1 through Root Y. Through Root X’s cross-sign the same ' +
      'bytes are outside the permitted subtree. Which chain you build decides which constraints apply — ' +
      'that is why path building and path validation cannot be separated carelessly.',
  },
  {
    id: 'eku',
    n: 7,
    title: 'EKU: certified for the wrong job',
    brief:
      'device.example.test presents a certificate whose chain is perfect and whose SAN matches — but its ' +
      'extendedKeyUsage lists clientAuth only, and you are validating it as a TLS SERVER certificate.',
    leafId: 'leaf-device',
    bagIds: ['issuing-b'],
    trustIds: ['root-y'],
    host: 'device.example.test',
    requiredEku: 'serverAuth',
    revokedIds: [],
    expectedVerdict: 'REJECT',
    culpritChecks: ['eku'],
    expectedSignatureOk: true,
    intendedPathIds: ['leaf-device', 'issuing-b', 'root-y'],
    lesson:
      'EKU scopes what a key was certified FOR. A clientAuth certificate serving TLS is a key doing a job ' +
      'its issuer never vouched for — the signature, which only proves who signed, has no opinion.',
  },
  {
    id: 'key-usage',
    n: 8,
    title: 'keyUsage: CA:TRUE but no keyCertSign',
    brief:
      'iot.example.test chains through NoCertSign CA: basicConstraints says CA:TRUE, but its keyUsage ' +
      'extension grants digitalSignature and cRLSign — not keyCertSign.',
    leafId: 'leaf-iot',
    bagIds: ['int-nosign'],
    trustIds: ['root-y'],
    host: 'iot.example.test',
    requiredEku: 'serverAuth',
    revokedIds: [],
    expectedVerdict: 'REJECT',
    culpritChecks: ['key-usage'],
    expectedSignatureOk: true,
    intendedPathIds: ['leaf-iot', 'int-nosign', 'root-y'],
    lesson:
      'Two independent extensions must BOTH say yes: basicConstraints (is this a CA?) and keyUsage (may ' +
      'this key sign certificates?). RFC 5280 §6.1.4 checks them separately — a verifier that treats ' +
      'CA:TRUE as sufficient re-creates this bug.',
  },
  {
    id: 'revoked',
    n: 9,
    title: 'Revoked intermediate',
    brief:
      'legacy.example.test chains through Retired CA. Every byte of every certificate is exactly as ' +
      'issued and every signature verifies — but the lab’s revocation fixture lists Retired CA as REVOKED.',
    leafId: 'leaf-legacy',
    bagIds: ['int-retired'],
    trustIds: ['root-y'],
    host: 'legacy.example.test',
    requiredEku: 'serverAuth',
    revokedIds: ['int-retired'],
    expectedVerdict: 'REJECT',
    culpritChecks: ['revocation'],
    expectedSignatureOk: true,
    intendedPathIds: ['leaf-legacy', 'int-retired', 'root-y'],
    lesson:
      'Revocation is the purest case of "validation is not signatures": nothing in the certificate ' +
      'changed. The status is an INPUT you must fetch (CRL or OCSP; here, a local fixture — this lab does ' +
      'no network fetch). A verifier that skips the lookup, or fails open when it is unreachable, accepts ' +
      'certificates their issuer has disowned.',
  },
  {
    id: 'self-signed',
    n: 10,
    title: 'A root of one’s own',
    brief:
      'standalone.example.test presents a single self-signed certificate: subject = issuer, and the ' +
      'signature genuinely verifies under its own public key. Your trust store holds Root X and Root Y.',
    leafId: 'leaf-standalone',
    bagIds: [],
    trustIds: ['root-x', 'root-y'],
    host: 'standalone.example.test',
    requiredEku: 'serverAuth',
    revokedIds: [],
    expectedVerdict: 'REJECT',
    culpritChecks: ['trust-anchor'],
    expectedSignatureOk: true,
    intendedPathIds: ['leaf-standalone'],
    lesson:
      'Self-signing is real cryptography and empty authority: anyone can sign their own claim with their ' +
      'own key. What separates this certificate from Root X is one thing only — Root X is in your trust ' +
      'store. Trust anchors are configuration, not mathematics.',
  },
];
