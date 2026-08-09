import { test } from '@playwright/test';
import { boot, driveAllStates, reportCollected, NARROW } from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven the way a visitor drives it: the locked pre-PKI state
 * measured before the panels unhide, the naive builder run to its alarm and the
 * backtracking builder run to its fix, all four puzzle grading branches reached
 * in an order that puts each next to the others, a stage graded on a truncated
 * path, the evidence deep-link followed into the inspector, the trust store
 * emptied and refilled, a root and a nameConstrained intermediate inspected,
 * and the bring-your-own-chain panel driven through garbage, a valid import and
 * a missing anchor. Every resulting state is scanned in both themes at desktop
 * and phone width — four configurations, because a gate that scans one scans
 * one half, and which half depends on the lab's defaults.
 *
 * See `gate.ts` for why nothing is injected into the page, why reduced motion
 * is asked for rather than forced (and why a style tag could never have
 * exercised this lab's reduced-motion block), why the defaults are asserted
 * rather than assumed, why every step is scanned rather than only the last, and
 * why `violations` is not the whole oracle.
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(1_800_000);
    await boot(page, theme);
    await driveAllStates(page, theme);
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(1_800_000);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    reportCollected();
  });
}
