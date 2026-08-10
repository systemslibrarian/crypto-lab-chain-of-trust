import AxeBuilder from '@axe-core/playwright';
import { expect, type Locator, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Five rules govern everything here, each of them a correction to the gate this
 * replaces:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The old gate pushed
 *     `animation: none !important; transition: none !important` through
 *     `addStyleTag`. This lab already ships exactly that declaration inside its
 *     own `@media (prefers-reduced-motion: reduce)` block — so the injection
 *     replaced the block with a copy of itself and could never have exercised
 *     it. Worse, `renderMechanism` reads
 *     `matchMedia('(prefers-reduced-motion: reduce)').matches` at render time
 *     to decide whether the builder steps in 650ms beats or lands at once, and
 *     a style tag cannot change what that query returns. The old gate was
 *     therefore relying on `contextOptions.reducedMotion` in
 *     `playwright.config.ts` for the behaviour it thought its style tag was
 *     providing, and asserting neither. `boot` asks for the preference on the
 *     page, asserts it took effect, injects nothing, and `settle` waits for
 *     whatever is running to drain.
 *
 *     The blanket `animation: none !important` in that block is the form that
 *     CAN destroy an end state — a cancelled animation loses it, where a
 *     zero-duration one still lands on it. It is safe here only because the lab
 *     declares no `@keyframes` at all; `expectNotBlank` is what keeps that true.
 *
 *  2. IT THREW AWAY EVERY STATE IT BUILT. `prepare()` ran both path builders,
 *     solved a puzzle stage, deep-linked to the inspector, flipped a trust
 *     root, failed and then re-ran the bring-your-own-chain panel — and then
 *     scanned ONCE, at the end. Each step overwrote the last: the naive
 *     builder's `.alarm` had been replaced by the backtracking builder's
 *     `.callout-ok`, the garbage-input alarm by a check table. Here every step
 *     is scanned.
 *
 *  3. IT NEVER SAW THE STATES THE LAB ARRIVES IN. It scanned one puzzle stage
 *     out of ten, always after grading; it never scanned the loading state, the
 *     ungraded stage, or the trust panel's default verdicts. See `boot`.
 *
 *  4. IT FORCE-OPENED WHAT A READER HAS TO CLICK, with
 *     `document.querySelectorAll('details').forEach(d => d.open = true)` — so
 *     the shut state was never scanned and the open one was never reached the
 *     way a reader reaches it.
 *
 *  5. `violations` IS NOT THE WHOLE ORACLE. See `scan`.
 */

/**
 * Soft-gate collection mode.
 *
 * Set `A11Y_COLLECT=1` and a run records every failed assertion instead of
 * stopping at the first, so a whole configuration's findings can be read off in
 * one pass and fixed together. Unset — which is every CI run, every local run,
 * and the default in every editor — `softExpect` is an ordinary strict
 * `expect`, so this costs the gate nothing.
 *
 * The one thing that must never happen is a collecting run being mistaken for a
 * passing gate. `reportCollected`, called at the end of every test, throws if
 * anything was recorded, so a collecting run with findings still exits red and
 * still prints them.
 */
const COLLECTING = process.env.A11Y_COLLECT === '1';
const collected: string[] = [];

function softExpect(received: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(received, message).toEqual(expected);
    return;
  }
  try {
    expect(received, message).toEqual(expected);
  } catch {
    collected.push(`${message}\n  ${JSON.stringify(received, null, 2).replace(/\n/g, '\n  ')}`);
  }
}

/** Fail a collecting run that recorded anything, after printing everything. */
export function reportCollected(): void {
  if (!COLLECTING || collected.length === 0) return;
  const report = collected.join('\n\n');
  collected.length = 0;
  throw new Error(
    `A11Y_COLLECT run recorded ${report.split('\n\n').length} failing assertions:\n\n${report}`
  );
}

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set. This lab's
 * reduced-motion block is the dangerous form, `animation: none !important` on
 * every element, and the only reason it is harmless is that the lab declares no
 * `@keyframes`. This assertion is what turns that from a fact someone once
 * checked into a fact the gate rechecks on every state, in every configuration.
 *
 * `aria-hidden` subtrees are excluded. The cost of that exclusion is stated
 * plainly: text removed from the accessibility tree AND painted at zero opacity
 * is not checked here.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  softExpect(invisible, `no visible text may render at opacity 0 in state: ${label}`, []);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert THE LAB'S DEFAULTS rather than assuming them.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page: an emulation that silently did nothing would
 * leave the gate certifying a different rendering than the one it claims to.
 * `playwright.config.ts` also sets `contextOptions.reducedMotion`, which the
 * claims suite depends on; the assertion here means the gate no longer depends
 * on it silently.
 *
 * The default assertions below are not decoration. A gate that scans one
 * configuration scans one half, and which half depends on the defaults. Three
 * of these decide what the rest of the drive is even looking at:
 *
 *  - THE PAGE ARRIVES LOCKED. All five panels ship `hidden` and are unhidden
 *    only after `generateLabPki()` returns 19 real ECDSA certificates. Until
 *    then the only thing on screen is `#loading`. That is a state every visitor
 *    passes through and no previous gate had measured, so it is asserted and
 *    measured here — narrowly, because it ends on its own schedule and a full
 *    axe pass would race it.
 *  - THE TRUST PANEL ALREADY SHOWS A REJECT. Both roots start trusted and the
 *    panel renders both cross-sign paths immediately, so `.chip-accept` (path
 *    B) and `.chip-reject` (path A, refused on nameConstraints) are BOTH on
 *    screen at first paint. The old gate unchecked Root X specifically "so a
 *    REJECT verdict renders there too" — it was already there, and the tone it
 *    was reaching for had been on the page the whole time, unscanned, because
 *    the one scan happened after everything else had also changed.
 *  - THE PUZZLE ARRIVES UNGRADED, on stage 1 with a path of one certificate,
 *    "Remove last certificate" disabled and no grade box. Every colour the
 *    grading branches paint is absent here, which is what makes this a distinct
 *    state worth scanning rather than a duller version of a later one.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful. 20s turns that silent hang
  // into a named failure naming the locator.
  page.setDefaultTimeout(20_000);
  // Playwright may run two of the four configurations in one worker process, so
  // a collecting run that died mid-drive could otherwise carry its findings into
  // the next test and report them against the wrong configuration.
  collected.length = 0;
  await page.emulateMedia({ reducedMotion: 'reduce' });
  // Both the anti-flash script in index.html's <head> and the shared header's
  // toggle use the key 'theme'; seeding it is the same route a returning
  // visitor takes.
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  // ── Make the locked state observable ─────────────────────────────────────
  // The lab PKI is 19 real ECDSA keypairs and it lands in about 70ms — shorter
  // than an axe pass, shorter than a contrast walk, shorter than a reliable
  // observation of any kind. So the JS bundle is held at the NETWORK layer for
  // long enough to scan the state a visitor arrives in, exactly as a slow
  // connection would hold it. Nothing is injected: no stylesheet, no media
  // query, no DOM, no attribute. Vite emits the CSS as its own `<link>`, so the
  // page below is fully styled while the module is still in flight — this
  // delays when the lab boots, not what it looks like.
  //
  // The bundle is held on an explicit release rather than a fixed sleep: a
  // sleep long enough to scan behind is also long enough to waste on every
  // configuration, and `unroute` while a handler is still sleeping leaves that
  // handler to call `continue()` on a route Playwright has already discarded.
  // The 60s race is a safety net so a failure before the release cannot hang
  // the request forever.
  let releaseBundle = (): void => {};
  const bundleHeld = new Promise<void>((resolve) => {
    releaseBundle = resolve;
  });
  await page.route(/assets\/.*\.js(\?.*)?$/, async (route) => {
    await Promise.race([bundleHeld, new Promise((r) => setTimeout(r, 60_000))]);
    await route.continue();
  });
  await page.goto('.', { waitUntil: 'commit' });
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  // ── The locked state, before the PKI exists ───────────────────────────────
  await expect(page.locator('#loading')).toContainText('Generating the lab PKI');
  for (const id of ['#mechanism', '#puzzle', '#truststore', '#inspector', '#byo']) {
    await expect(page.locator(id)).toBeHidden();
  }
  await scan(page, `${theme} / locked: PKI still generating, every panel hidden`);

  releaseBundle();
  await expect(page.locator('#loading')).toContainText('ready', { timeout: 60_000 });

  // ── Every panel unhidden ──────────────────────────────────────────────────
  for (const id of ['#mechanism', '#puzzle', '#truststore', '#inspector', '#byo']) {
    await expect(page.locator(id)).toBeVisible();
  }
  await expect(page.locator('details[open]')).toHaveCount(0);

  // ── Panel 1: the builder has not run ──────────────────────────────────────
  await expect(page.locator('#mechanism .step-log-list li')).toHaveCount(0);
  await expect(page.locator('#mechanism .alarm')).toHaveCount(0);
  await expect(page.locator('#mechanism .callout-ok')).toHaveCount(0);
  await expect(page.locator('#mechanism .node')).toHaveCount(5);
  await expect(page.locator('#mechanism .diamond-scroll')).toHaveAttribute('tabindex', '0');
  await expect(page.locator('#mechanism .step-log')).toHaveAttribute('tabindex', '0');

  // ── Panel 2: stage 1, one certificate, ungraded ───────────────────────────
  await expect(page.locator('#puzzle .score-line')).toHaveText('Solved 0 of 10 stages.');
  await expect(page.locator('#puzzle .cert-list').first().locator('li')).toHaveCount(1);
  await expect(page.getByRole('button', { name: 'Remove last certificate' })).toBeDisabled();
  await expect(page.locator('#puzzle .check-table')).toHaveCount(0);
  await expect(page.locator('#puzzle .chip')).toHaveCount(0);

  // ── Panel 3: both roots trusted, and BOTH verdict tones already painted ───
  await expect(page.locator('#trust-x')).toBeChecked();
  await expect(page.locator('#trust-y')).toBeChecked();
  await expect(page.locator('#truststore .chip-accept')).toHaveCount(1);
  await expect(page.locator('#truststore .chip-reject')).toHaveCount(1);
  await expect(page.locator('#truststore .chip-fact')).toHaveCount(2);

  // ── Panel 4: the inspector opens on the leaf, with its DER dump ───────────
  await expect(page.locator('#inspector .kv-table')).toBeVisible();
  await expect(page.locator('#inspector .der-dump')).toHaveAttribute('tabindex', '0');
  await expect(page.locator('#inspector .kv-evidence')).toHaveCount(0);

  // ── Panel 5: nothing pasted, nothing run ──────────────────────────────────
  await expect(page.locator('#byo-chain')).toHaveValue('');
  await expect(page.locator('#byo-trust')).toHaveValue('');
  await expect(page.locator('#byo .check-table')).toHaveCount(0);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is a
 * plausible offender at 380px: the inspector prints unbreakable hex tokens
 * (serial numbers, subject and authority key identifiers), the check tables run
 * four columns wide, and three of its five panels lay out as two-column grids
 * whose bare `1fr` tracks take a min-content floor.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow-x: auto` wrapper has a huge bounding rect
    // but is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. That
    // cost a run elsewhere in this fleet, and this lab has an obvious decoy:
    // `.diamond-wrap` is `min-width: 37rem` on purpose and is 250px wider than
    // a phone viewport in every single state.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    // Prefer an unclipped culprit; fall back to the widest clipped one rather
    // than reporting nothing, so the message always names something to look at.
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  softExpect(overflow, `page must not scroll horizontally in state: ${label}`, null);
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 *
 * This lab already got the three obvious ones right — `.diamond-scroll`,
 * `.step-log` and `.der-dump` each carry `tabindex="0"` and a name. The
 * assertion is kept because those three are set from three different modules
 * and a fourth scroller is one `max-height` away, and because the ones authors
 * miss are the containers that only overflow after a long run: `.step-log` is
 * capped at 18rem and a backtracking run puts a dozen entries in it.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  softExpect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`,
    []
  );
}

/**
 * A `.scroll-region` must be a focus target exactly while it is scrolling.
 *
 * `expectScrollersReachable` above catches one half of that — a scroller a
 * keyboard cannot reach. This catches the other half, which is not a WCAG
 * failure but is the claim `scrollRegion` makes: a check table that fits its
 * card must not leave a tab stop that does nothing. The two together are what
 * make the ResizeObserver in `common.ts` an assertion rather than an intention,
 * and they are checked in all four configurations, which is the only way to see
 * both states of a box whose behaviour depends on the viewport.
 */
export async function expectScrollRegionsTabbableIffScrolling(
  page: Page,
  label: string
): Promise<void> {
  const wrong = await page.evaluate(() =>
    Array.from(document.querySelectorAll<HTMLElement>('.scroll-region'))
      .map((el) => ({
        el,
        scrolls: el.scrollWidth > el.clientWidth + 1,
        tabbable: el.hasAttribute('tabindex'),
      }))
      .filter((x) => x.scrolls !== x.tabbable)
      .map(
        (x) =>
          `${x.el.getAttribute('aria-label') ?? '(unnamed)'} — scrolls=${x.scrolls} ` +
          `tabbable=${x.tabbable} (${x.el.scrollWidth} in ${x.el.clientWidth})`
      )
  );
  softExpect(wrong, `scroll regions must be tabbable iff scrolling in state: ${label}`, []);
}

/**
 * Scan the page as it currently stands.
 *
 * Five assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically — which matters more here than in most labs, since
 *    every verdict tone on the page is a translucent fill or a `color-mix()`
 *    axe declines to resolve. Everything else in that bucket is a real result
 *    axe simply could not finish — including `aria-prohibited-attr`, which is
 *    where an `aria-label` on a role-less div hides, a defect that never
 *    reaches the violations array at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no text
 * node. Both were being found by hand-sampling screenshot pixels, which does
 * not regress-test.
 *
 * The backlog is real, so this does not block on it — but a check that merely
 * logs is not a gate, and this sweep has spent its whole length deleting checks
 * that could not fail. So it ratchets instead: anything NOT in the baseline
 * fails, anything in the baseline that got WORSE fails, and anything in the
 * baseline that has been FIXED fails until its entry is deleted. That last rule
 * is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it. Opt-in via env, and the run is
  // deliberately left failing at the end by `expectBaselineNotStale` so a
  // capture pass can never be mistaken for a passing gate.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(
        `WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`
      );
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  await expectNoNewNonTextFailures(page, label);
  await expectScrollersReachable(page, label);
  await expectScrollRegionsTabbableIffScrolling(page, label);
  await expectNoHorizontalOverflow(page, label);
}

/**
 * Open one `<details>` the way a reader does — by clicking its summary.
 *
 * Takes a Locator rather than a selector string on purpose. Three of this
 * lab's disclosures share the class `.scope-note` (the honest-scope note, the
 * two glossaries and every stage hint), so a `.first()` on a class selector
 * silently picks whichever happens to come first in the panel — and if that one
 * is already open, the click CLOSES it and the assertion below is the only
 * thing that notices. Callers name the one they mean.
 */
async function openDisclosure(d: Locator): Promise<void> {
  await d.locator('> summary').click();
  await expect(d).toHaveAttribute('open', '');
}

/**
 * Build the full intended path for the current puzzle stage by pressing
 * "Add to path" until nothing is left enabled.
 *
 * The bag is offered in the order the stage declares, and each press re-renders
 * the list, so the locator is re-resolved every iteration rather than held.
 */
async function buildFullPath(page: Page): Promise<void> {
  for (let guard = 0; guard < 12; guard++) {
    const add = page.locator('#puzzle button:enabled').filter({ hasText: 'Add to path' });
    if ((await add.count()) === 0) return;
    await add.first().click();
  }
  throw new Error('the bag never emptied — "Add to path" stayed enabled for 12 presses');
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Four things shape this drive:
 *
 *  - THE WRONG ANSWERS ARE THE EXHIBIT. This lab's whole subject is a valid
 *    signature that must still be refused, and its colour system says so: a
 *    monochrome `.chip-fact` beside a coloured `.chip-accept` / `.chip-reject`
 *    / `.chip-unknown`. Every one of the four grading branches paints a
 *    different box — `.alarm` for accepting a chain the validator rejects,
 *    `.callout-plain` for "too strict" and for "right verdict, wrong reason",
 *    `.callout-ok` for correct — and all four are driven, in an order that puts
 *    each next to the others.
 *
 *  - THE PANELS ARRIVE IN STATES NO CLICK RETURNS TO. The naive builder's
 *    `.alarm` is destroyed by the backtracking run; the ungraded puzzle stage
 *    is destroyed by the first ruling; the trust panel's default pair of
 *    verdicts is destroyed by the first checkbox. `boot` asserts and scans
 *    those before anything is pressed.
 *
 *  - THE STEP LOG ONLY OVERFLOWS AFTER A LONG RUN. `.step-log` is capped at
 *    18rem and `appendStep` scrolls it to the bottom, so its scrollbar — and
 *    the WCAG 2.1.1 question that comes with it — exists only once a builder
 *    has actually run. Both runs are scanned.
 *
 *  - `<details>` ARE OPENED BY THEIR SUMMARIES. The named ones (honest scope,
 *    the two glossaries, the stage hint) are opened and scanned one at a time.
 *    A check table's ten per-row `<details>` are opened together and scanned
 *    once: they are ten instances of one rendering, and scanning each would add
 *    forty minutes and no coverage.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  await scanAt('first paint, PKI ready, nothing driven');

  await page.locator('a.cl-skip-link').focus();
  await scanAt('skip link focused');

  await openDisclosure(page.locator('.intro .scope-note'));
  await scanAt('honest-scope disclosure open');

  // ── Panel 1 — the two builders ───────────────────────────────────────────
  // The naive run is the historical bug on display: it finds one valid chain,
  // validation refuses it on nameConstraints, and it never backtracks.
  await page.getByRole('button', { name: /Run the NAIVE builder/i }).click();
  await expect(page.locator('#mechanism .alarm')).toBeVisible();
  await expect(page.locator('#mechanism .node-rejected').first()).toBeVisible();
  await expect(page.locator('#mechanism .step-tag-bad').first()).toBeVisible();
  await scanAt('naive builder finished: no chain found, alarm shown');

  await page.locator('#mechanism .step-log').focus();
  await scanAt('step log focused');

  await page.getByRole('button', { name: /Run the BACKTRACKING builder/i }).click();
  await expect(page.locator('#mechanism .callout-ok')).toBeVisible();
  await expect(page.locator('#mechanism .node-accepted').first()).toBeVisible();
  await expect(page.locator('#mechanism .step-tag-ok').first()).toBeVisible();
  await expect(page.locator('#mechanism .step-tag-warn').first()).toBeVisible();
  await scanAt('backtracking builder finished: valid path found');

  await page.locator('#mechanism .diamond-scroll').focus();
  await scanAt('diagram scroller focused');

  // ── Panel 2 — the puzzle, all four grading branches ──────────────────────
  await openDisclosure(page.locator('#puzzle details.scope-note').first());
  await scanAt('puzzle glossary open');

  // Stage 1 is the valid chain. Rule REJECT on it first: that is the "too
  // strict" branch, the only one that renders `.callout-plain` beside an
  // ACCEPT verdict chip.
  await buildFullPath(page);
  await expect(page.locator('#puzzle .cert-list').first().locator('li')).toHaveCount(3);
  await scanAt('stage 1 path assembled, not yet ruled');

  await page.locator('#puzzle button', { hasText: 'REJECT' }).first().click();
  await expect(page.locator('#puzzle .chip-accept')).toBeVisible();
  await expect(page.locator('#puzzle .callout-plain')).toBeVisible();
  await expect(page.locator('#puzzle .status-pass').first()).toBeVisible();
  await scanAt('stage 1 ruled REJECT — too strict, every check passes');

  await openDisclosure(page.locator('#puzzle .check-detail details').first());
  await scanAt('one check-table detail open');

  // Open the rest of the row disclosures together — ten instances of one
  // rendering — and scan the fully expanded table once.
  const details = page.locator('#puzzle .check-detail details:not([open]) > summary');
  for (let i = await details.count(); i > 0; i = await details.count()) {
    await details.first().click();
  }
  await scanAt('every check-table row expanded');

  await page.getByRole('button', { name: 'ACCEPT this chain' }).click();
  await expect(page.locator('#puzzle .callout-ok')).toBeVisible();
  await scanAt('stage 1 ruled ACCEPT — correct, stage solved');
  await expect(page.locator('#puzzle .score-line')).toHaveText('Solved 1 of 10 stages.');

  // Stage 2 is the CA:FALSE classic: every signature verifies and the chain
  // must still be refused. ACCEPT it to reach the `.alarm` state — the one
  // rendering in this lab where the fact chip and the verdict chip disagree.
  await page.getByRole('button', { name: /^2\. The classic/ }).click();
  await expect(page.locator('#puzzle .check-table')).toHaveCount(0);
  await scanAt('stage 2 selected, ungraded');

  await buildFullPath(page);
  await page.getByRole('button', { name: 'ACCEPT this chain' }).click();
  await expect(page.locator('#puzzle .alarm')).toBeVisible();
  await expect(page.locator('#puzzle .chip-reject')).toBeVisible();
  await expect(page.locator('#puzzle .status-fail').first()).toBeVisible();
  await scanAt('stage 2 wrongly ACCEPTED — alarm, valid signatures and all');

  // Right verdict, wrong reason: REJECT with the wrong check named.
  await page.locator('#puzzle select').selectOption('hostname');
  await page.locator('#puzzle button', { hasText: /^REJECT$/ }).first().click();
  await expect(page.locator('#puzzle .callout-plain')).toContainText('Right verdict, wrong reason');
  await scanAt('stage 2 ruled REJECT with the wrong culprit');

  await page.locator('#puzzle select').selectOption('basic-constraints');
  await page.locator('#puzzle button', { hasText: /^REJECT$/ }).first().click();
  await expect(page.locator('#puzzle .callout-ok')).toBeVisible();
  await expect(page.locator('#puzzle .score-line')).toHaveText('Solved 2 of 10 stages.');
  await scanAt('stage 2 solved, lesson shown');

  // The graded-on-a-partial-path branch, and the undo control that reaches it.
  await page.getByRole('button', { name: 'Remove last certificate' }).click();
  await expect(page.getByRole('button', { name: 'Remove last certificate' })).toBeEnabled();
  await page.locator('#puzzle button', { hasText: /^REJECT$/ }).first().click();
  await expect(page.locator('#puzzle .lede').last()).toContainText('graded on the path exactly as you built it');
  await scanAt('stage 2 graded on a truncated path');

  // Stage 9 is the revoked intermediate, the one stage whose failing check
  // comes from outside the certificates entirely.
  await page.getByRole('button', { name: /^9\. Revoked intermediate/ }).click();
  await buildFullPath(page);
  // The hint, not the glossary: both are `.scope-note`, and the glossary is
  // already open from earlier in this drive, so a positional selector here
  // would have closed it instead.
  await openDisclosure(
    page.locator('#puzzle details.scope-note').filter({ hasText: 'Need a nudge?' })
  );
  await scanAt('stage 9 hint open, path assembled');

  await page.locator('#puzzle select').selectOption('revocation');
  await page.locator('#puzzle button', { hasText: /^REJECT$/ }).first().click();
  await expect(page.locator('#puzzle .callout-ok')).toBeVisible();
  await scanAt('stage 9 solved — revoked intermediate');

  // The evidence deep-link is the only route to `.kv-evidence` / the amber
  // `.badge-evidence` in the inspector.
  await page.getByRole('button', { name: /Open the evidence for/i }).first().click();
  await expect(page.locator('#inspector .kv-evidence').first()).toBeVisible();
  await expect(page.locator('#inspector .badge-evidence').first()).toBeVisible();
  await scanAt('inspector opened on the evidence rows');

  await page.getByRole('button', { name: 'Reset all stages' }).click();
  await expect(page.locator('#puzzle .score-line')).toHaveText('Solved 0 of 10 stages.');
  await expect(page.locator('#puzzle .check-table')).toHaveCount(0);
  await scanAt('all stages reset');

  // ── Panel 3 — trust is configuration ─────────────────────────────────────
  await page.getByLabel('Trust Root X').uncheck();
  await expect(page.locator('#truststore .chip-reject')).toHaveCount(1);
  await scanAt('Root X untrusted');

  // Both roots off: no anchors at all, so both paths fail and the panel is
  // entirely reject-toned — the only state with no `.chip-accept` in it.
  await page.getByLabel('Trust Root Y').uncheck();
  await expect(page.locator('#truststore .chip-accept')).toHaveCount(0);
  await expect(page.locator('#truststore .chip-reject')).toHaveCount(2);
  await scanAt('empty trust store, both paths rejected');

  await page.getByLabel('Trust Root X').check();
  await page.getByLabel('Trust Root Y').check();
  await expect(page.locator('#truststore .chip-accept')).toHaveCount(1);
  await scanAt('both roots trusted again');

  // ── Panel 4 — the inspector, one certificate of each shape ───────────────
  // A root: self-issued, no SAN, no EKU, no nameConstraints — the shortest
  // key/value table the panel ever renders.
  await page.locator('#inspector .inspect-nav button').first().click();
  await expect(page.locator('#inspector .kv-evidence')).toHaveCount(0);
  await scanAt('inspector showing a root certificate');

  // The constrained intermediate: the only certificate carrying a
  // nameConstraints row.
  await page
    .getByRole('button', { name: 'Issuing CA (cross-sign A, via Root X)', exact: true })
    .click();
  await expect(page.locator('#inspector .kv-table')).toContainText('nameConstraints');
  await scanAt('inspector showing the nameConstrained intermediate');

  await page.locator('#inspector .der-dump').focus();
  await scanAt('DER dump focused');

  // ── Panel 5 — bring your own chain ───────────────────────────────────────
  await openDisclosure(page.locator('#byo details.scope-note').first());
  await scanAt('bring-your-own glossary open');

  // Fail-closed on garbage: the parser's own alarm, no check table at all.
  await page.locator('#byo-chain').fill('not a certificate');
  await page.getByRole('button', { name: /Validate my chain/ }).click();
  await expect(page.locator('#byo .alarm')).toBeVisible();
  await expect(page.locator('#byo .check-table')).toHaveCount(0);
  await scanAt('bring-your-own rejected garbage input');

  await page.getByRole('button', { name: /Load the lab/i }).click();
  await expect(page.locator('#byo-chain')).toContainText('');
  await expect(page.locator('#byo .alarm')).toHaveCount(0);
  await scanAt('lab chain loaded as an example, not yet validated');

  // A pasted chain has no revocation source, so an otherwise-valid chain gets
  // UNKNOWN — the only place `.chip-unknown` and `.status-unknown` are painted.
  await page.getByRole('button', { name: /Validate my chain/ }).click();
  await expect(page.locator('#byo .chip-unknown')).toBeVisible();
  await expect(page.locator('#byo .status-unknown')).toBeVisible();
  await expect(page.locator('#byo .check-table')).toBeVisible();
  // The table's four columns have a ~385px min-content width, so at 380px it
  // must be scrolling inside its region and that region must be a focus target
  // — and at 1280px it must be neither. `scan` asserts the invariant on every
  // state; this asserts the two concrete halves, so a fix that quietly stopped
  // scrolling (or quietly stopped needing to) is not mistaken for a pass.
  const byoRegion = page.locator('#byo .scroll-region');
  if ((page.viewportSize()?.width ?? 1280) < 640) {
    await expect(byoRegion).toHaveAttribute('tabindex', '0');
  } else {
    await expect(byoRegion).not.toHaveAttribute('tabindex', /.*/);
  }
  await scanAt('imported chain validated: UNKNOWN, revocation not evaluated');

  // Drop the anchors: a chain that parses but reaches no trust anchor.
  await page.locator('#byo-trust').fill('');
  await page.getByRole('button', { name: /Validate my chain/ }).click();
  await expect(page.locator('#byo .alarm')).toBeVisible();
  await scanAt('imported chain with no trust anchors');
}
