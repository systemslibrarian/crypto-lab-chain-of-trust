# Chain of Trust — X.509 path building & validation (RFC 5280)

A real X.509 hierarchy the learner must validate by hand, showing that **finding a chain and
validating a chain are two different problems — and only one of them is about signatures**.

## What It Is

An interactive, browser-only demo of **X.509 certification path building and path validation**
(RFC 5280 §6, with RFC 6125/RFC 9525 server identity). On load it generates a fresh PKI in your
browser — two roots, a **cross-signed issuing CA** (one key, two certificates), and a branch of
deliberately defective intermediates and leaves — 19 certificates of real DER, each carrying a real
**ECDSA P-256** (FIPS 186-4) signature made through WebCrypto via
[`@peculiar/x509`](https://github.com/PeculiarVentures/x509). The RFC 5280 checks
(basicConstraints, pathLenConstraint, keyUsage, nameConstraints, EKU, validity, trust anchoring),
the hostname matcher, and both path builders are hand-rolled, inspectable TypeScript in
`src/pki/`.

The concept it teaches: **a valid signature on a certificate means someone signed it. It says
nothing about whether that someone was allowed to.** Path building is search; path validation is a
checklist of constraints that have nothing to do with cryptography — and the checklist is where
the bugs live. Throughout the UI the cryptographic result and the security verdict are rendered as
two separate indicators; `Signature: valid ✓ / Verdict: REJECT ✗` is the whole lab in one line.

Security model honesty: revocation statuses are **local fixtures** (no CRL/OCSP network fetch —
deliberately, since the point is that revocation is an *input* to validation). This is a teaching
subset of RFC 5280 §6 — no policy mapping, no IP/email name constraints, no ASN.1 hardening.
**Not production crypto — a teaching demo.**

## Exhibits

1. **Building a path ≠ validating it** — the headline mechanism. A cross-signed diamond:
   `leaf → cross-sign A → Root X` is cryptographically flawless but fails nameConstraints;
   `leaf → cross-sign B → Root Y` is valid. Run the **naive builder** (commits to the first
   signature-valid issuer, no backtracking) and watch it report *no valid chain* for a leaf that
   has one — the bug class that made OpenSSL 1.0.2 clients reject valid Let's Encrypt chains when
   DST Root X3 expired in September 2021. Then run the **backtracking builder** (RFC 4158 style)
   on the same bytes and watch it recover. Every step in the animation is a real ECDSA
   verification or a real validator run.
2. **You are the validator** — puzzle mode, ten stages, learner-triggered one at a time. Each
   stage hands you a leaf, a bag of intermediates, and a trust store; you assemble the path and
   rule ACCEPT or REJECT (naming the failing check). Grading runs the real RFC 5280 §6
   implementation on the exact path you built and tells you which check you missed. Every stage
   carries a hint that points where to look without naming the check (a test enforces that),
   every failed check links straight to its evidence — the exact certificate fields, highlighted
   in the inspector — and a plain-language glossary sits where the jargon first bites. The trap
   ladder: valid baseline · basicConstraints CA:FALSE (the classic — signature fine, authority
   absent, cf. iOS CVE-2011-0228) · pathLenConstraint exceeded · expired intermediate under a
   fresh leaf · hostname vs SAN vs deprecated CN fallback · nameConstraints subtree violation ·
   EKU mismatch (clientAuth cert validated for serverAuth) · keyUsage lacking keyCertSign ·
   revoked intermediate (fixture status) · self-signed leaf presented as its own root. In every
   REJECT stage the signature chain is fully valid — that is the lab's thesis, and it is pinned by
   a test.
3. **Same chain, different trust store** — both cross-sign paths re-validated live under every
   combination of trusted roots. The bytes and ECDSA results never change; the verdicts do.
   Trust is configuration, not mathematics.
4. **Certificate inspector** — every certificate in the lab: parsed fields, decoded extensions
   (where all the authority lives), full DER hex, and a live signature verdict against every
   candidate issuer key.
5. **Bring your own chain** — paste any real PEM chain plus the anchors you choose to trust, and
   run the same builder and validator against it, entirely in the tab (nothing is uploaded or
   fetched). Revocation for imported chains is reported honestly as NOT EVALUATED, never as a
   clean pass. A one-click example loads the lab's own chain as editable PEM — flip one base64
   character and watch the signature check fail.

## When to Use It

- To learn or teach why X.509 validation is a *checklist*, not a signature check — before reading
  RFC 5280 §6 itself.
- To understand real incidents: CA:FALSE acceptance bugs, the DST Root X3 expiry, cross-signing
  and why "which chain did you build?" changes the answer.
- To build intuition for why trust stores — pure configuration — decide what the same mathematics
  means.
- **Do NOT use it** as a validation library, as a reference implementation for production path
  validation, or as evidence that a particular client behaves a particular way. The validator here
  is a teaching subset; production validators handle policy constraints, name forms, and encodings
  this lab deliberately omits.

## Live Demo

**<https://systemslibrarian.github.io/crypto-lab-chain-of-trust/>**

Run both builders on the cross-signed diamond, play the ten validator stages (try accepting the
CA:FALSE chain and read the alarm), flip roots in and out of the trust store, and read the DER of
anything you don't believe.

## What Can Go Wrong

Each is a stage in the puzzle; each shipped somewhere as a real bug:

- **Skipping basicConstraints** — any website's key becomes a CA (iOS CVE-2011-0228 class).
- **Not backtracking during path building** — "no valid chain" for leaves with valid chains
  (OpenSSL 1.0.2 / DST Root X3, September 2021).
- **CN fallback** — accepting a certificate for a host its SAN never named.
- **Ignoring nameConstraints, pathLen, or keyUsage** — delegated authority silently escapes the
  territory or depth it was granted.
- **Failing open on revocation** — accepting certificates their issuer has disowned.
- **Trusting the presented "root"** — a self-signed certificate is real cryptography and empty
  authority.

## Real-World Usage

Every TLS client runs this algorithm on every connection: browsers (Chrome's verifier, Apple's,
Mozilla NSS), OpenSSL/BoringSSL/rustls, and OS trust stores. Cross-signing is how new roots
bootstrap (ISRG Root X1 via DST Root X3); nameConstraints scope enterprise and government CAs;
EKU and keyUsage separation is CA/Browser Forum baseline policy. The failures this lab stages are
drawn from that history, with the honest caveat that each real incident had its own specific
failing check.

## How to Run Locally

```bash
npm install
npm run dev        # serves on http://localhost:5173
npm test           # 77 unit tests incl. 6 KATs
npm run build      # typecheck + production build
npm run test:a11y  # axe-core WCAG 2.1 A/AA gate, both themes (build first)
```

Requires Node 20+ (WebCrypto). No backend; keys are generated per session in memory and never
persisted.

## Related Demos

- [crypto-lab-tls-handshake](https://systemslibrarian.github.io/crypto-lab-tls-handshake/) — the
  protocol these certificates arrive inside.
- [crypto-lab-pki-chain](https://systemslibrarian.github.io/crypto-lab-pki-chain/) — PKI chains
  with Certificate Transparency, the public-log answer to mis-issuance.
- [crypto-lab-web-of-trust](https://systemslibrarian.github.io/crypto-lab-web-of-trust/) — the
  decentralized alternative to hierarchical trust.
- [crypto-lab-ecdsa-forge](https://systemslibrarian.github.io/crypto-lab-ecdsa-forge/) — the
  signature primitive itself, and how it fails.

## Build & Verify

- **77 Vitest tests** (`npm test`), including **6 known-answer tests** in `src/pki/kat.test.ts`:
  2 SHA-256 KATs (FIPS 180-4) and 4 ECDSA P-256 verification KATs (RFC 6979 §A.2.5 vectors — two
  accept, two must-reject), all through the same WebCrypto the demo uses.
- Behavioral tests pin the validator against **every stage of the trap ladder** (verdict, failing
  check, and the signature-chain fact independently), the naive-vs-backtracking builder outcomes,
  hostname matching, nameConstraints subtree semantics, PEM import round-trips, and invariants:
  any failed check forces REJECT, the builder never revisits a certificate, and empty/duplicate
  paths fail closed.
- Extending the lab? Read [docs/MAINTAINERS.md](docs/MAINTAINERS.md) — validator check order,
  stage-authoring rules, and why the fact/verdict split is non-negotiable.
- **Accessibility is gated in CI**: `npm run test:a11y` scans the production build with
  axe-core (WCAG 2.1 A/AA) in **both** themes plus a 390px mobile viewport — after driving the
  live demo into its alarm states — and the GitHub Pages deploy in
  `.github/workflows/deploy.yml` is blocked if it fails.

## Performance

PKI generation (19 ECDSA P-256 keypairs + certificates) takes well under a second in a modern
browser; every validator run is a handful of WebCrypto verifications and completes in
milliseconds.

---

*One of 170+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
