# What Would Make This the Gold Standard

## Bottom line

This repo is already close. The hard part is present and verified: real cryptography, an honest teaching scope, a strong test bar, an accessibility gate, and a clear thesis that separates cryptographic fact from security verdict.

I verified the current quality bar locally:

- `npm test`: 67/67 passing
- `npm run build`: passing
- `npm run test:a11y`: 3/3 passing

What would move this from excellent to gold-standard is not more RFC breadth first. The next gains are about transfer, explorable state, and maintainability:

1. Let learners apply the validator to unfamiliar or real chains.
2. Make the search problem more explorable, not just observable.
3. Reduce the translation burden for newcomers at the moment they get stuck.
4. Make the repo easier for instructors and contributors to extend without weakening the lesson.

## What is already best-in-class

- The core teaching thesis is unusually crisp: `signature valid` is visibly separate from `ACCEPT/REJECT`, and that distinction is enforced across the UI and validator.
- The architecture is already modular in the right places: path building in [src/pki/build.ts](src/pki/build.ts), validation in [src/pki/validate.ts](src/pki/validate.ts), scenario design in [src/pki/scenarios.ts](src/pki/scenarios.ts), and learner-facing panels in [src/ui](src/ui).
- The repo is honest about scope in both [README.md](README.md) and [index.html](index.html): teaching subset, no fake math, no dishonest production claims.
- The quality floor is real rather than aspirational: unit tests, production build, GitHub Pages workflow, and Playwright accessibility checks are all wired and passing.

That means the highest-leverage work is no longer “make it correct.” It is “make it transfer, stick, and scale.”

## Highest-leverage improvements

| Priority | Improvement | Why it matters | Natural surface |
| --- | --- | --- | --- |
| P0 | Bring your own chain mode | This is the clearest jump from lab to real-world use. Let a learner paste a PEM leaf plus intermediates, choose a host, provide a trust store, and run the same validator and inspector. That turns the demo into a tool for understanding real failures without changing the honest no-backend model. | [src/main.ts](src/main.ts), [src/pki/validate.ts](src/pki/validate.ts), [src/ui/inspector.ts](src/ui/inspector.ts) |
| P0 | Search playground for path building | The current mechanism is strong, but it is still a guided run. Expose bag ordering, choice points, dead ends, and backtracking as an interactive search tree so learners can feel why a naive builder fails. | [src/pki/build.ts](src/pki/build.ts), [src/ui/mechanism.ts](src/ui/mechanism.ts) |
| P0 | Link failed checks directly to the offending evidence | When the learner gets `nameConstraints` or `keyUsage` wrong, they should be able to click that failing check and jump straight to the exact certificate and field that caused it. That removes a lot of novice friction without dumbing anything down. | [src/ui/puzzle.ts](src/ui/puzzle.ts), [src/ui/inspector.ts](src/ui/inspector.ts), [src/ui/common.ts](src/ui/common.ts) |
| P1 | Just-in-time glossary and plain-language translations | Terms like trust anchor, EKU, SAN, CN fallback, and excluded subtree are still expensive for first-time learners. Add short popovers or side notes at the exact point of confusion rather than a separate wall of docs. | [src/pki/scenarios.ts](src/pki/scenarios.ts), [src/ui/puzzle.ts](src/ui/puzzle.ts), [index.html](index.html) |
| P1 | Real-world incident bridge inside the UI | The repo already references incidents like DST Root X3 and CA:FALSE acceptance. Surface those mappings in the app itself so each stage clearly answers “when did this matter in production?” | [src/pki/scenarios.ts](src/pki/scenarios.ts), [README.md](README.md), [index.html](index.html) |
| P1 | Shareable state and exported transcripts | If a learner or instructor can share a URL that captures the current stage, built path, trust-store toggles, and verdict, this becomes much more usable in classrooms, bug reports, and self-study. A “copy validation transcript” action would also help. | [src/main.ts](src/main.ts), [src/ui/puzzle.ts](src/ui/puzzle.ts), [src/ui/trust.ts](src/ui/trust.ts) |
| P1 | Contributor and instructor docs | The learner-facing README is strong, but a gold-standard repo also explains how to extend itself safely: validator check order, stage authoring rules, why the fact/verdict split is non-negotiable, and how to add new failure modes without diluting the thesis. | [README.md](README.md), new maintainer docs |
| P2 | Cross-browser smoke tests and deeper invariants | The accessibility gate is excellent, but the quality bar would climb further with a small cross-browser interaction suite and a few invariant-style tests around malformed chains, loop avoidance, and “any failed check means reject.” | [playwright.config.ts](playwright.config.ts), [e2e/a11y.spec.ts](e2e/a11y.spec.ts), [src/pki/build.test.ts](src/pki/build.test.ts), [src/pki/validate.test.ts](src/pki/validate.test.ts) |
| P2 | Performance budget in CI | The current build is reasonable, but gold-standard repos protect their future state. Add a bundle budget before more features land, especially if inspector affordances or imported-chain parsing grow the JS payload. | [package.json](package.json), CI workflow |
| P2 | Teacher mode / compare-good-vs-bad path view | A side-by-side view of the intended path and a nearby failing path would make several stages teach faster, especially CA:FALSE, hostname, and nameConstraints. This is a strong classroom affordance, but less important than transfer and evidence-linking. | [src/ui/puzzle.ts](src/ui/puzzle.ts), [src/ui/trust.ts](src/ui/trust.ts) |

## Recommended order of attack

If the goal is maximum impact with minimum scope creep, I would do the work in this order.

### Phase 1: tighten the current lesson

- Add direct links from failed checks to the relevant certificate and extension in the inspector.
- Add a lightweight glossary for the small set of RFC terms that still block newcomers.
- Add a short maintainer guide for stage authoring and validator invariants.
- Add a few targeted builder/validator invariant tests and one small cross-browser smoke test.

This keeps the current product shape intact while making it easier to learn and safer to extend.

### Phase 2: make it transfer outside the lab

- Build a paste-your-own-chain flow.
- Add shareable URLs and exported transcripts.
- Add a real-world incidents panel tied to the existing stages.

This is the step that would make the demo useful after the first visit, not just during it.

### Phase 3: turn path building into a full exploration surface

- Build the search playground around bag order, choice points, dead ends, and backtracking.
- Add compare-good-vs-bad path views where it helps the learner most.

This is the highest teaching upside, but it is also the most product work. It is worth doing after the transfer and evidence-linking layers are in place.

## What I would not prioritize yet

- Do not broaden the validator toward full production RFC 5280 coverage before the current lesson becomes more explorable and reusable.
- Do not add more puzzle stages just to increase count. The current ten stages are strong enough; the bigger gain is making those ten easier to internalize and apply.
- Do not add network CRL/OCSP fetching just to feel more “real.” The current fixture model is honest and keeps the teaching point clear.
- Do not spend the next cycle on visual restyling. The main gap is not aesthetics; it is transfer and explorable state.

## If I could only choose three things

1. Bring your own chain mode.
2. Search playground for the builder.
3. Click-through evidence linking from failed checks to inspector fields.

Those three changes would do the most to move this from a very strong teaching demo to something people point to as the reference implementation for how to teach X.509 path building and validation on the web.