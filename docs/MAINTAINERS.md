# Maintainer guide — extending Chain of Trust without weakening the lesson

This lab teaches one thing: **a valid signature is not a verdict.** Every rule in this document
exists to protect that thesis. If a change conflicts with an invariant here, the invariant wins.

## Non-negotiable invariants

1. **Fact/verdict separation.** The cryptographic result (`signatureChainOk`, the monochrome
   `chip-fact`) and the security verdict (`verdict`, the colored `chip-accept`/`chip-reject`)
   are computed independently and rendered as separate indicators. Never merge them, never derive
   one from the other in the UI, never color the signature chip green.
2. **Color tracks system integrity, never raw return values.** A learner accepting a chain the
   validator rejects renders as ALARM (`.alarm`), even though every signature is "valid". State is
   never conveyed by color alone — always icon + text + color.
3. **Real crypto only.** Every signature verdict shown anywhere must come from a live WebCrypto
   ECDSA verification over real DER (via `cert.verify(...)`). Defects are semantic — extensions,
   dates, trust configuration — never faked bytes or stubbed verify calls.
4. **Fail closed.** Malformed input (imported PEM, empty paths) throws or rejects with a plain
   message; it never yields a partial result. Deliberately broken modes (the naive builder) are
   never the default and are visibly labeled broken.
5. **Honest revocation.** Statuses are local fixtures for lab certs and **NOT EVALUATED** for
   imported chains (`revocationSource: 'not-evaluated'`). Never render an unchecked thing as a
   clean pass; never add network CRL/OCSP fetching (see scope note in the README).

## Validator check order (src/pki/validate.ts)

Checks run in this order and are ALL reported, independently — the verdict is
`ACCEPT` iff every check passes:

1. `trust-anchor` — DER byte-equality against the trust store (configuration, not crypto)
2. `signature` — one result per link, plus a self-signature check only when the top cert claims
   subject == issuer (the one cryptographic check; feeds `signatureChainOk`)
3. `validity` — every certificate in the path, not just the leaf
4. `basic-constraints` — every issuing cert must assert CA:TRUE
5. `key-usage` — issuing certs with a keyUsage extension must assert keyCertSign
6. `path-len` — anchor→leaf walk with decrementing budget (anchor's own pathLen is enforced as
   local policy, documented in the check detail)
7. `name-constraints` — dNSName subtrees only, accumulated anchor→leaf, checked against SANs
8. `eku` — leaf only, only when the scenario demands a purpose (EKU-absent = unrestricted per
   RFC 5280; the divergence from CABF practice is stated in the detail text)
9. `revocation` — fixture lookup or explicit NOT EVALUATED
10. `hostname` — RFC 6125/9525, SAN-only, run only when a host is given

If you add a check: give it a `CheckId`, an RFC citation, a plain-language pass detail AND fail
detail, decide `certId` attribution, add an `EVIDENCE_ROWS` mapping in `src/ui/inspector.ts`,
and extend `CHECK_NAMES` in `src/ui/common.ts` so the puzzle's reject dropdown offers it.

## Adding a puzzle stage (the trap ladder)

A stage must isolate **one** lesson. Checklist:

1. **Generate the defect for real** in `src/pki/certgen.ts` — a new branch of certs whose only
   flaw is the semantic one you're teaching. Give ids like `int-foo` / `leaf-foo`.
2. **Author the stage** in `src/pki/scenarios.ts`. Required fields:
   - `culpritChecks`: every check that fails (naming any of them counts as correct — see the
     CA:FALSE stage, where `basic-constraints` and `key-usage` both honestly fail).
   - `expectedSignatureOk`: almost always `true` — that IS the thesis. A stage where the
     signature fails is teaching something else; think twice.
   - `hint`: points where to look **without naming the failing check**. A test enforces that the
     hint text does not contain any `culpritChecks` id; keep synonyms honest too.
   - `lesson`: shown only after solving; cite the real-world incident precisely or not at all
     (a slightly-overstated attack claim is an honesty violation, not a flourish).
3. **Tests come free** — `validate.test.ts` iterates `STAGES` and pins verdict, failing-check
   set, and the signature fact. Run `npm test` and the new stage is covered. Add a targeted test
   only if the defect has interesting edges (like the pathLen decrement).
4. **Don't inflate the ladder.** Ten stages that isolate cleanly beat fifteen that overlap.

## Quality gates (all must pass before push)

```bash
npm test           # unit tests + KATs — never skip, never mark todo
npm run build      # tsc --noEmit + vite build
npm run test:a11y  # axe WCAG 2.1 A/AA: dark, light, and 390px mobile, zero violations
```

The GitHub Pages deploy (`.github/workflows/deploy.yml`) runs the same three and blocks on any
failure. Author UI to the checklist in `CRYPTO-LAB-TEMPLATE.md` §4.2 (contrast tokens, no
color-only state, focusable scroll regions, live regions for async output).

## Scope guard

The in-page "What this lab isn't" list is binding: no TLS handshake, no CT log, no network
revocation, no ASN.1 fuzzing, no issuance/ACME. When a request is adjacent to one of those,
link the sibling demo instead of rebuilding it here.
