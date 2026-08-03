import { expect, test, type Locator, type Page } from '@playwright/test';

/**
 * Claims gate. The a11y suite proves the page is reachable; this suite proves
 * it is right. Everything asserted here is a claim the lab makes on screen or
 * in its README — the builder verdicts, the ten puzzle stages, the trust-store
 * matrix, the inspector's decoded fields, and the imported-chain verdicts —
 * re-derived and cross-checked rather than string-matched in isolation.
 *
 * The lab's thesis is one line: `Signature: valid ✓ / Verdict: REJECT ✗`.
 * Almost every assertion below exists to hold the two halves of that line
 * apart, so a change that quietly merges cryptography and authority fails.
 */

async function boot(page: Page): Promise<void> {
  await page.goto('.');
  await expect(page.locator('#loading')).toContainText('ready', { timeout: 30_000 });
  await expect(page.locator('#mechanism')).toBeVisible();
}

/** Step-log action tags, in order, for the most recent builder run. */
async function logTags(page: Page): Promise<string[]> {
  return page.locator('#mechanism .step-tag').allTextContents();
}

/** Node id -> state class suffix ('', 'accepted', 'rejected', 'active'). */
async function diagramStates(page: Page): Promise<Record<string, string>> {
  return page.locator('#mechanism .node').evaluateAll((nodes) =>
    Object.fromEntries(
      nodes.map((n) => [
        n.getAttribute('data-node')!,
        (n.className.match(/node-(\w+)/)?.[1] ?? ''),
      ]),
    ),
  );
}

/** Labels of the checks reported as ✗ FAIL in a check table. */
async function failedChecks(scope: Locator): Promise<string[]> {
  return scope.locator('.check-table .status-fail').evaluateAll((tds) =>
    tds.map((td) => (td.nextElementSibling as HTMLElement).childNodes[0]!.textContent!.trim()),
  );
}

/** Click every enabled "Add to path" button, in the order the bag lists them. */
async function buildFullPath(page: Page): Promise<void> {
  for (;;) {
    const add = page.getByRole('button', { name: 'Add to path' }).and(page.locator(':enabled'));
    if ((await add.count()) === 0) break;
    await add.first().click();
  }
}

const gradeBox = (page: Page) => page.locator('#puzzle [role="status"]').last();

/** The inspector's certificate heading (the nav's group headings are h3 too). */
const certHeading = (page: Page) => page.locator('#inspector .inspector-cols > div h3').first();

// ─── Exhibit 1 — building a path ≠ validating it ──────────────────────────────

test('the naive builder fails a leaf that has a valid path, and says why', async ({ page }) => {
  await boot(page);
  await page.getByRole('button', { name: /run the naive builder/i }).click();
  await expect(page.locator('#mechanism .alarm')).toBeVisible({ timeout: 30_000 });

  // The search: it commits to cross-sign A, validation kills it on policy, and
  // it never returns. No BACKTRACK step exists in this run — that is the bug.
  const tags = await logTags(page);
  expect(tags).toContain('PATH-REJECTED');
  expect(tags).toContain('GIVE-UP');
  expect(tags).not.toContain('BACKTRACK');
  expect(tags).not.toContain('PATH-ACCEPTED');
  expect(tags.filter((t) => t === 'VALIDATE')).toHaveLength(1); // one path, tried once

  const steps = await page.locator('#mechanism .step-log-list li').allTextContents();
  // README: "Every step in the animation is a real ECDSA verification or a real
  // validator run" — the link steps must claim a real verification, by name.
  const linkSteps = steps.filter((s) => s.startsWith('LINK-OK'));
  expect(linkSteps.length).toBeGreaterThan(0);
  for (const s of linkSteps) expect(s).toContain('Real ECDSA verify');

  // The rejection is policy, not cryptography — the whole point of the lab.
  const rejection = steps.find((s) => s.startsWith('PATH-REJECTED'))!;
  expect(rejection).toContain('nameConstraints');
  expect(rejection).toContain('signature chain is fully valid');
  expect(rejection).toContain('no cryptography was harmed');

  const alarm = (await page.locator('#mechanism .alarm').textContent())!;
  expect(alarm).toContain('no valid chain — connection fails');
  expect(alarm).toContain('cross-sign B → Root Y'); // the path it should have found
  expect(alarm).toContain('DST Root X3');
  expect(alarm).toContain('OpenSSL 1.0.2');

  // The diagram must show the same story the log tells: the A-branch condemned,
  // the B-branch never even looked at.
  expect(await diagramStates(page)).toEqual({
    'leaf-www': 'rejected',
    'issuing-a': 'rejected',
    'root-x': 'rejected',
    'issuing-b': '',
    'root-y': '',
  });
  await expect(page.locator('#mechanism .edge-rejected')).toHaveCount(2);
  await expect(page.locator('#mechanism .edge-accepted')).toHaveCount(0);
});

test('the backtracking builder recovers, and its counter matches its own log', async ({ page }) => {
  await boot(page);
  await page.getByRole('button', { name: /run the backtracking builder/i }).click();
  await expect(page.locator('#mechanism .callout-ok')).toBeVisible({ timeout: 30_000 });

  const tags = await logTags(page);
  // It rejects the A-branch exactly as the naive builder did, then keeps going.
  expect(tags).toContain('PATH-REJECTED');
  expect(tags).toContain('BACKTRACK');
  expect(tags).toContain('PATH-ACCEPTED');
  expect(tags).not.toContain('GIVE-UP');
  expect(tags.indexOf('BACKTRACK')).toBeGreaterThan(tags.indexOf('PATH-REJECTED'));
  expect(tags.indexOf('PATH-ACCEPTED')).toBeGreaterThan(tags.indexOf('BACKTRACK'));

  const outcome = (await page.locator('#mechanism .callout-ok').textContent())!;
  expect(outcome).toContain('Backtracking found the valid path');
  expect(outcome).toContain('leaf → cross-sign B → Root Y');
  expect(outcome).toContain('not one byte, not one signature');

  // The counter is not decorative: "Candidate paths validated: N" must equal
  // the number of times the log actually handed a path to the validator.
  const claimed = Number(/Candidate paths validated: (\d+)/.exec(outcome)![1]);
  expect(claimed).toBe(tags.filter((t) => t === 'VALIDATE').length);
  expect(claimed).toBe(2); // A rejected, B accepted

  expect(await diagramStates(page)).toEqual({
    'leaf-www': 'accepted',
    'issuing-a': 'rejected',
    'root-x': '', // cleared by the backtrack step
    'issuing-b': 'accepted',
    'root-y': 'accepted',
  });
});

test('both builders see identical cryptography — only the search differs', async ({ page }) => {
  await boot(page);
  await page.getByRole('button', { name: /run the naive builder/i }).click();
  await expect(page.locator('#mechanism .alarm')).toBeVisible({ timeout: 30_000 });
  const naive = await page.locator('#mechanism .step-log-list li').allTextContents();

  await page.getByRole('button', { name: /run the backtracking builder/i }).click();
  await expect(page.locator('#mechanism .callout-ok')).toBeVisible({ timeout: 30_000 });
  const smart = await page.locator('#mechanism .step-log-list li').allTextContents();

  // The claim "not one byte, not one signature changed" is checkable: the
  // backtracking log must open with the naive log, step for step, and only
  // then continue past the point where the naive builder quit.
  expect(smart.slice(0, naive.length - 1)).toEqual(naive.slice(0, naive.length - 1));
  expect(smart.length).toBeGreaterThan(naive.length);

  // And the branch the naive builder died on is the branch Section 3 reports
  // as REJECT under the same store — the two panels must agree.
  const pathA = page.locator('#truststore .trust-path').first();
  await expect(pathA.locator('.chip-reject')).toHaveText('Verdict: REJECT ✗');
  await expect(pathA).toContainText('Fails: nameConstraints (territory).');
});

// ─── Exhibit 3 — trust is configuration, not mathematics ─────────────────────

test('the same bytes get four different verdicts from four trust stores, with the signature facts frozen', async ({ page }) => {
  await boot(page);
  const cardA = page.locator('#truststore .trust-path').nth(0);
  const cardB = page.locator('#truststore .trust-path').nth(1);
  const trustX = page.getByLabel('Trust Root X');
  const trustY = page.getByLabel('Trust Root Y');

  // Both paths carry three real ECDSA verifications; that fact must be
  // identical in every one of the four configurations below.
  const FACT = 'Signature: valid ✓ (all 3 real ECDSA verifications pass)';

  // X ✓ Y ✓ — A is anchored but out of territory; B is clean.
  await expect(cardA.locator('.chip-reject')).toBeVisible();
  await expect(cardA).toContainText('Fails: nameConstraints (territory).');
  await expect(cardB.locator('.chip-accept')).toHaveText('Verdict: ACCEPT ✓');
  await expect(cardB).toContainText('Every check passes under this store.');
  await expect(cardA.locator('.chip-fact')).toHaveText(FACT);
  await expect(cardB.locator('.chip-fact')).toHaveText(FACT);

  // X ✗ Y ✓ — dropping Root X strips A of its anchor as well.
  await trustX.uncheck();
  await expect(cardA).toContainText('Trust anchor');
  await expect(cardA.locator('.chip-reject')).toBeVisible();
  await expect(cardB.locator('.chip-accept')).toBeVisible();
  await expect(cardA.locator('.chip-fact')).toHaveText(FACT);

  // X ✓ Y ✗ — now the path that was ACCEPT becomes REJECT. Same bytes.
  await trustX.check();
  await trustY.uncheck();
  await expect(cardB.locator('.chip-reject')).toHaveText('Verdict: REJECT ✗');
  await expect(cardB).toContainText('Trust anchor');
  await expect(cardB.locator('.chip-fact')).toHaveText(FACT);

  // Neither trusted — nothing anchors, though every signature still verifies.
  await trustX.uncheck();
  await expect(cardA.locator('.chip-reject')).toBeVisible();
  await expect(cardB.locator('.chip-reject')).toBeVisible();
  await expect(cardA).toContainText('Trust anchor');
  await expect(cardB).toContainText('Trust anchor');
  await expect(cardA.locator('.chip-fact')).toHaveText(FACT);
  await expect(cardB.locator('.chip-fact')).toHaveText(FACT);

  // Restoring the store restores the verdict — no hidden state was mutated.
  await trustX.check();
  await trustY.check();
  await expect(cardB.locator('.chip-accept')).toHaveText('Verdict: ACCEPT ✓');
});

// ─── Exhibit 2 — the ten-stage trap ladder ───────────────────────────────────

interface StageExpectation {
  n: number;
  /** The path is built by adding every offered certificate, except stage 10. */
  addNone?: boolean;
  verdict: 'ACCEPT' | 'REJECT';
  /** Value of the "…because this check fails" option to pick. */
  culprit: string | null;
  /** Exactly the checks that must report ✗ FAIL for the intended path. */
  fails: string[];
}

const STAGE_EXPECTATIONS: StageExpectation[] = [
  { n: 1, verdict: 'ACCEPT', culprit: null, fails: [] },
  {
    n: 2,
    verdict: 'REJECT',
    culprit: 'basic-constraints',
    fails: ['basicConstraints (CA authority)', 'keyUsage (keyCertSign)'],
  },
  { n: 3, verdict: 'REJECT', culprit: 'path-len', fails: ['pathLenConstraint (depth budget)'] },
  { n: 4, verdict: 'REJECT', culprit: 'validity', fails: ['Validity window'] },
  { n: 5, verdict: 'REJECT', culprit: 'hostname', fails: ['Server identity (host "www.example.test")'] },
  { n: 6, verdict: 'REJECT', culprit: 'name-constraints', fails: ['nameConstraints (territory)'] },
  { n: 7, verdict: 'REJECT', culprit: 'eku', fails: ['extendedKeyUsage (serverAuth)'] },
  { n: 8, verdict: 'REJECT', culprit: 'key-usage', fails: ['keyUsage (keyCertSign)'] },
  { n: 9, verdict: 'REJECT', culprit: 'revocation', fails: ['Revocation status (local fixture)'] },
  // Stage 10's intended path is the self-signed leaf alone: adding the roots
  // would be building a different (and signature-invalid) chain.
  { n: 10, addNone: true, verdict: 'REJECT', culprit: 'trust-anchor', fails: ['Trust anchor'] },
];

test('all ten stages: the intended path is graded correct, and every REJECT has flawless signatures', async ({ page }) => {
  test.setTimeout(120_000);
  await boot(page);
  const stageBtns = page.locator('#puzzle .stage-list button');
  await expect(stageBtns).toHaveCount(10); // README: ten stages

  for (const stage of STAGE_EXPECTATIONS) {
    const label = `stage ${stage.n}`;
    await stageBtns.nth(stage.n - 1).click();
    if (!stage.addNone) await buildFullPath(page);

    if (stage.verdict === 'ACCEPT') {
      await page.getByRole('button', { name: 'ACCEPT this chain' }).click();
    } else {
      await page.locator('#puzzle select').selectOption(stage.culprit!);
      await page.getByRole('button', { name: 'REJECT', exact: true }).click();
    }

    const box = gradeBox(page);
    await expect(box.locator('.callout-ok'), label).toContainText('✓ Correct.');
    await expect(box.locator('.chip-fact'), label).toContainText('Signature: valid ✓');
    await expect(
      box.locator(stage.verdict === 'ACCEPT' ? '.chip-accept' : '.chip-reject'),
      label,
    ).toHaveText(stage.verdict === 'ACCEPT' ? 'Verdict: ACCEPT ✓' : 'Verdict: REJECT ✗');

    // The lab's thesis, pinned stage by stage: a REJECT whose cryptography is
    // perfect. If a stage ever starts failing on the signature instead of the
    // constraint it is meant to teach, this is where it shows up.
    if (stage.verdict === 'REJECT') {
      await expect(box.locator('.callout-ok'), label).toContainText('the cryptography is flawless');
    }

    // Exactly the intended checks fail — no more, no fewer.
    expect(await failedChecks(box), label).toEqual(stage.fails);
    // ...and the verdict follows from them: REJECT iff something failed.
    expect(stage.fails.length > 0, label).toBe(stage.verdict === 'REJECT');

    // Solving the stage unlocks its lesson and marks the nav entry.
    await expect(box, label).toContainText('Lesson:');
    await expect(stageBtns.nth(stage.n - 1), label).toHaveClass(/stage-solved/);
    await expect(page.locator('#puzzle .score-line'), label).toHaveText(
      `Solved ${stage.n} of 10 stages.`,
    );
  }

  // The score counter must equal the number of stages actually marked solved.
  await expect(page.locator('#puzzle .stage-list button.stage-solved')).toHaveCount(10);
  await expect(page.locator('#puzzle .score-line')).toHaveText('Solved 10 of 10 stages.');

  // Reset really resets — no stage stays credited.
  await page.getByRole('button', { name: 'Reset all stages' }).click();
  await expect(page.locator('#puzzle .score-line')).toHaveText('Solved 0 of 10 stages.');
  await expect(page.locator('#puzzle .stage-list button.stage-solved')).toHaveCount(0);
});

test('accepting a chain the validator rejects raises the alarm and names exactly the failed checks', async ({ page }) => {
  await boot(page);
  await page.locator('#puzzle .stage-list button').nth(1).click(); // 2. CA:FALSE
  await buildFullPath(page);
  await page.getByRole('button', { name: 'ACCEPT this chain' }).click();

  const box = gradeBox(page);
  const alarm = box.locator('.alarm');
  await expect(alarm).toContainText('You accepted a chain the RFC 5280 validator rejects');
  // The alarm's own explanation must not soften the thesis.
  await expect(alarm).toContainText('every signature in your chain is genuinely valid');
  await expect(box.locator('.chip-fact')).toContainText('Signature: valid ✓');
  await expect(box.locator('.chip-reject')).toHaveText('Verdict: REJECT ✗');

  // "The check you missed: X; Y." must list exactly the ✗ FAIL rows below it.
  const text = (await alarm.textContent())!;
  const missed = /The check you missed: (.+)\.$/.exec(text.trim())![1]!.split('; ');
  expect(missed).toEqual(await failedChecks(box));
  expect(missed).toEqual(['basicConstraints (CA authority)', 'keyUsage (keyCertSign)']);

  // A wrong ruling does not credit the stage.
  await expect(page.locator('#puzzle .score-line')).toHaveText('Solved 0 of 10 stages.');
  await expect(page.locator('#puzzle .stage-list button.stage-solved')).toHaveCount(0);
});

test('right verdict for the wrong reason is not a pass', async ({ page }) => {
  await boot(page);
  await page.locator('#puzzle .stage-list button').nth(1).click(); // 2. CA:FALSE
  await buildFullPath(page);

  // Blame the hostname check, which passes here.
  await page.locator('#puzzle select').selectOption('hostname');
  await page.getByRole('button', { name: 'REJECT', exact: true }).click();
  const box = gradeBox(page);
  await expect(box).toContainText('Right verdict, wrong reason:');
  await expect(box).toContainText('you blamed "Hostname (SAN does not match the host)"');
  await expect(box).toContainText('what actually fails is: basicConstraints (CA authority); keyUsage (keyCertSign)');
  await expect(page.locator('#puzzle .score-line')).toHaveText('Solved 0 of 10 stages.');

  // Rejecting without naming a check is also not a pass.
  await page.locator('#puzzle select').selectOption('');
  await page.getByRole('button', { name: 'REJECT', exact: true }).click();
  await expect(gradeBox(page)).toContainText('pick the failing check from the list');
  await expect(page.locator('#puzzle .score-line')).toHaveText('Solved 0 of 10 stages.');

  // Naming the real check finally credits it.
  await page.locator('#puzzle select').selectOption('key-usage');
  await page.getByRole('button', { name: 'REJECT', exact: true }).click();
  await expect(gradeBox(page)).toContainText('✓ Correct.');
  await expect(page.locator('#puzzle .score-line')).toHaveText('Solved 1 of 10 stages.');
});

test('rejecting a valid chain is graded as too strict, not as correct', async ({ page }) => {
  await boot(page);
  await page.locator('#puzzle .stage-list button').nth(0).click(); // 1. valid baseline
  await buildFullPath(page);
  await page.locator('#puzzle select').selectOption('validity');
  await page.getByRole('button', { name: 'REJECT', exact: true }).click();

  const box = gradeBox(page);
  await expect(box).toContainText('Too strict:');
  await expect(box).toContainText('the validator accepts this path — every check passes');
  await expect(box.locator('.chip-accept')).toHaveText('Verdict: ACCEPT ✓');
  expect(await failedChecks(box)).toEqual([]);
  await expect(page.locator('#puzzle .score-line')).toHaveText('Solved 0 of 10 stages.');
});

test('an incomplete path is graded as built, and does not credit the stage', async ({ page }) => {
  await boot(page);
  await page.locator('#puzzle .stage-list button').nth(1).click(); // 2. CA:FALSE
  // Add only the first intermediate: the path never reaches an anchor.
  await page.getByRole('button', { name: 'Add to path' }).and(page.locator(':enabled')).first().click();
  await page.locator('#puzzle select').selectOption('basic-constraints');
  await page.getByRole('button', { name: 'REJECT', exact: true }).click();

  const box = gradeBox(page);
  await expect(box).toContainText('You were graded on the path exactly as you built it');
  // Un-anchored is itself a failure — the validator must not quietly anchor it.
  expect(await failedChecks(box)).toContain('Trust anchor');
  await expect(page.locator('#puzzle .score-line')).toHaveText('Solved 0 of 10 stages.');
});

test('every failed check links to the certificate field that decided it', async ({ page }) => {
  await boot(page);
  await page.locator('#puzzle .stage-list button').nth(1).click(); // 2. CA:FALSE
  await buildFullPath(page);
  await page.locator('#puzzle select').selectOption('basic-constraints');
  await page.getByRole('button', { name: 'REJECT', exact: true }).click();

  await page.getByRole('button', { name: /Open the evidence for "basicConstraints/ }).click();
  // The evidence is the actual field, on the actual certificate that failed.
  await expect(certHeading(page)).toHaveText(
    'Server Ops (CA:FALSE end-entity)',
  );
  const evidence = page.locator('#inspector .kv-evidence');
  await expect(evidence).toHaveCount(1);
  await expect(evidence).toContainText('basicConstraints');
  await expect(evidence).toContainText('CA:FALSE');

  // A different check highlights different rows — the mapping is not a constant.
  await page.locator('#puzzle .stage-list button').nth(5).click(); // 6. nameConstraints
  await buildFullPath(page);
  await page.locator('#puzzle select').selectOption('name-constraints');
  await page.getByRole('button', { name: 'REJECT', exact: true }).click();
  await page.getByRole('button', { name: /Open the evidence for "nameConstraints/ }).click();
  await expect(page.locator('#inspector .kv-evidence')).toContainText('subjectAltName');
  await expect(page.locator('#inspector .kv-evidence')).toContainText('www.example.test');
});

// ─── Exhibit 4 — the inspector shows the bytes the verdicts came from ────────

test('the inspector holds all 19 certificates and decodes the fields the stages turn on', async ({ page }) => {
  await boot(page);
  const nav = page.locator('#inspector .inspect-nav button');
  await expect(nav).toHaveCount(19); // README: "19 certificates"

  const rowText = async (key: string) =>
    (await page.locator('#inspector .kv-table tr', { hasText: key }).first().locator('td').textContent())!;

  const open = async (name: string) => {
    await nav.filter({ hasText: name }).first().click();
    await expect(certHeading(page)).toHaveText(name);
  };

  // Each of these fields is the exact reason a puzzle stage rejects.
  await open('Server Ops (CA:FALSE end-entity)');
  expect(await rowText('basicConstraints')).toContain('CA:FALSE');

  await open('Constrained CA (pathLen=0)');
  expect(await rowText('basicConstraints')).toContain('CA:TRUE, pathLenConstraint=0');

  await open('NoCertSign CA (CA:TRUE, no keyCertSign)');
  expect(await rowText('basicConstraints')).toContain('CA:TRUE');
  expect(await rowText('keyUsage')).not.toContain('keyCertSign');

  await open('Issuing CA (cross-sign A, via Root X)');
  expect(await rowText('nameConstraints')).toContain('internal.test');

  await open('CN=www / SAN=shop (leaf)');
  expect(await rowText('subjectAltName')).toBe('shop.example.test');
  expect(await rowText('Subject')).toContain('CN=www.example.test'); // the CN that lies

  await open('device.example.test (clientAuth leaf)');
  expect(await rowText('extendedKeyUsage')).toContain('clientAuth');
  expect(await rowText('extendedKeyUsage')).not.toContain('serverAuth');
});

test('cross-signing is visible in the bytes: one key, two certificates', async ({ page }) => {
  await boot(page);
  const nav = page.locator('#inspector .inspect-nav button');
  await nav.filter({ hasText: 'www.example.test (leaf)' }).first().click();
  await expect(certHeading(page)).toHaveText('www.example.test (leaf)');

  // The leaf was signed once, but BOTH cross-sign certificates carry the same
  // key — so a live ECDSA verdict against every candidate issuer must show two
  // passes. That is what "cross-signed: one key, two certificates" means.
  const verdicts = (await page
    .locator('#inspector .kv-table tr', { hasText: 'Signature verdict (live ECDSA)' })
    .locator('td')
    .textContent())!;
  expect(verdicts.match(/✓ verifies/g) ?? []).toHaveLength(2);
  expect(verdicts).toContain('cross-sign A');
  expect(verdicts).toContain('cross-sign B');
  expect(verdicts).not.toContain('✗ does not verify');
});

test('the DER dump contains exactly as many bytes as its header claims', async ({ page }) => {
  await boot(page);
  const nav = page.locator('#inspector .inspect-nav button');
  for (const name of ['Root Y', 'www.example.test (leaf)', 'Expired CA']) {
    await nav.filter({ hasText: name }).first().click();
    await expect(certHeading(page)).toHaveText(name);
    const header = (await page.locator('#inspector h3').last().textContent())!;
    const claimed = Number(/DER encoding \((\d+) bytes/.exec(header)![1]);
    const dump = (await page.locator('#inspector .der-dump').textContent())!.trim();
    expect(dump.split(/\s+/), name).toHaveLength(claimed);
    expect(dump, name).toMatch(/^[0-9a-f]{2}( [0-9a-f]{2})*$/);
    // Every X.509 certificate is a DER SEQUENCE: tag 0x30.
    expect(dump.slice(0, 2), name).toBe('30');
  }
});

// ─── Exhibit 5 — bring your own chain ────────────────────────────────────────

test('imported chains fail closed on unparseable input', async ({ page }) => {
  await boot(page);
  await page.locator('#byo-chain').fill('not a certificate');
  await page.getByRole('button', { name: 'Validate my chain' }).click();
  const alarm = page.locator('#byo .alarm');
  await expect(alarm).toContainText('Input rejected (fail closed)');
  await expect(alarm).toContainText('no "-----BEGIN CERTIFICATE-----" blocks found');
  await expect(page.locator('#byo .check-table')).toHaveCount(0); // no verdict at all

  // An empty trust store is also refused, rather than silently trusting nothing
  // and reporting a bare REJECT that looks like a validation result.
  await page.getByRole('button', { name: /load the lab/i }).click();
  await page.locator('#byo-trust').fill('');
  await page.getByRole('button', { name: 'Validate my chain' }).click();
  await expect(page.locator('#byo .alarm')).toContainText('Input rejected (fail closed)');
});

test("the lab's own chain imports to UNKNOWN — never a clean ACCEPT", async ({ page }) => {
  await boot(page);
  await page.getByRole('button', { name: /load the lab/i }).click();
  // The example really is PEM the user could have pasted.
  const pem = await page.locator('#byo-chain').inputValue();
  expect(pem.match(/-----BEGIN CERTIFICATE-----/g)).toHaveLength(2);
  expect(await page.locator('#byo-trust').inputValue()).toContain('-----BEGIN CERTIFICATE-----');

  await page.getByRole('button', { name: 'Validate my chain' }).click();
  await expect(page.locator('#byo .check-table')).toBeVisible({ timeout: 15_000 });

  const byo = page.locator('#byo');
  await expect(byo.locator('.chip-fact')).toContainText('Signature: valid ✓');
  await expect(byo.locator('.chip-unknown')).toHaveText('Verdict: UNKNOWN — revocation not evaluated');
  await expect(byo.locator('.chip-accept')).toHaveCount(0);

  // UNKNOWN is exactly "nothing failed, but something was not evaluated".
  expect(await failedChecks(byo)).toEqual([]);
  await expect(byo.locator('.status-unknown')).toHaveCount(1);
  await expect(byo.locator('.check-table tbody tr', { hasText: 'Revocation status — NOT EVALUATED' })).toHaveCount(1);
  await expect(byo).toContainText('no CRL/OCSP fetch');
});

test('flipping one base64 character breaks the signature check, exactly as the README promises', async ({ page }) => {
  await boot(page);
  await page.getByRole('button', { name: /load the lab/i }).click();
  const pem = await page.locator('#byo-chain').inputValue();

  // Corrupt one character inside the leaf's signature bytes: still valid PEM,
  // still parses as DER, no longer verifies.
  const lines = pem.split('\n');
  const target = lines.findIndex((l) => l.includes('END CERTIFICATE')) - 2;
  const line = lines[target]!;
  lines[target] = line.slice(0, 10) + (line[10] === 'A' ? 'B' : 'A') + line.slice(11);
  expect(lines.join('\n')).not.toBe(pem);

  await page.locator('#byo-chain').fill(lines.join('\n'));
  await page.getByRole('button', { name: 'Validate my chain' }).click();
  await expect(page.locator('#byo .check-table')).toBeVisible({ timeout: 15_000 });

  const byo = page.locator('#byo');
  // The one case where the crypto really is the problem — and the fact chip
  // must say so, instead of blaming a policy check.
  await expect(byo.locator('.chip-fact')).toHaveText('Signature: INVALID ✗ (a link fails real ECDSA verification)');
  await expect(byo.locator('.chip-reject')).toHaveText('Verdict: REJECT ✗');
  const fails = await failedChecks(byo);
  expect(fails.some((f) => f.startsWith('Signature:'))).toBe(true);
  await expect(byo.locator('.check-table')).toContainText('does NOT verify');
  // The builder cannot rescue a chain whose link does not verify.
  await expect(byo).toContainText('No valid path found');
});

test('an imported chain is judged for the host and purpose you name, not the one it was made for', async ({ page }) => {
  await boot(page);
  await page.getByRole('button', { name: /load the lab/i }).click();
  const byo = page.locator('#byo');

  // Same bytes, wrong host: policy fails, cryptography does not. No candidate
  // path survives, so the panel falls back to the chain exactly as pasted —
  // which stops one certificate short of the anchor, and says so.
  await page.locator('#byo-host').fill('evil.example.test');
  await page.getByRole('button', { name: 'Validate my chain' }).click();
  await expect(byo.locator('.check-table')).toBeVisible({ timeout: 15_000 });
  await expect(byo.locator('.chip-fact')).toContainText('Signature: valid ✓');
  await expect(byo.locator('.chip-reject')).toHaveText('Verdict: REJECT ✗');
  await expect(byo).toContainText('No valid path found');
  expect(await failedChecks(byo)).toEqual([
    'Trust anchor',
    'Server identity (host "evil.example.test")',
  ]);

  // Same bytes, wrong purpose: a serverAuth leaf validated as a TLS client cert.
  await page.locator('#byo-host').fill('www.example.test');
  await page.locator('#byo-eku').selectOption('clientAuth');
  await page.getByRole('button', { name: 'Validate my chain' }).click();
  await expect(byo.locator('.check-table')).toBeVisible({ timeout: 15_000 });
  await expect(byo.locator('.chip-fact')).toContainText('Signature: valid ✓');
  expect(await failedChecks(byo)).toEqual(['Trust anchor', 'extendedKeyUsage (clientAuth)']);

  // Drop both requirements and the same bytes come back to UNKNOWN.
  await page.locator('#byo-eku').selectOption('serverAuth');
  await page.getByRole('button', { name: 'Validate my chain' }).click();
  await expect(byo.locator('.check-table')).toBeVisible({ timeout: 15_000 });
  await expect(byo.locator('.chip-unknown')).toBeVisible();
  expect(await failedChecks(byo)).toEqual([]);
});
