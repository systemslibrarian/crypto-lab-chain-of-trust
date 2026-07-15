import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/**
 * Reveal collapsed content and drive the live demo so every dynamic region —
 * the builder step log, the puzzle grade box (including the ALARM state), the
 * trust-store verdicts, the inspector — is in the DOM when axe scans.
 */
async function prepare(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{animation:none!important;transition:none!important}`,
  });

  // Wait for the PKI to generate and the panels to unhide.
  await expect(page.locator('#loading')).toContainText('ready', { timeout: 30_000 });
  await expect(page.locator('#mechanism')).toBeVisible();

  // Run both path builders (naive first; each run disables the buttons until done).
  await page.getByRole('button', { name: /run the naive builder/i }).click();
  await expect(page.locator('#mechanism .alarm')).toBeVisible({ timeout: 30_000 });
  await page.getByRole('button', { name: /run the backtracking builder/i }).click();
  await expect(page.locator('#mechanism .callout-ok')).toBeVisible({ timeout: 30_000 });

  // Puzzle: go to stage 2 (CA:FALSE), build the full chain, then wrongly
  // ACCEPT it — that renders the alarm state, which must also pass contrast.
  await page.getByRole('button', { name: /2\. The classic/ }).click();
  for (;;) {
    const add = page.getByRole('button', { name: 'Add to path' }).and(page.locator(':enabled'));
    if ((await add.count()) === 0) break;
    await add.first().click();
  }
  await page.getByRole('button', { name: 'ACCEPT this chain' }).click();
  await expect(page.locator('#puzzle .alarm')).toBeVisible();

  // Trust panel: flip a root off so a REJECT verdict renders there too.
  await page.getByLabel('Trust Root X').uncheck();

  // Open every <details> so hidden explanatory text is scanned.
  await page.evaluate(() => {
    document.querySelectorAll('details').forEach((d) => (d.open = true));
  });
  await page.waitForTimeout(400);
}

async function scan(page: Page): Promise<void> {
  const { violations } = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  expect(
    violations.map((v) => ({
      id: v.id,
      impact: v.impact,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
    })),
  ).toEqual([]);
}

test('no WCAG A/AA violations — dark theme', async ({ page }) => {
  await page.goto('.');
  await prepare(page);
  await scan(page);
});

test('no WCAG A/AA violations — light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await prepare(page);
  await scan(page);
});
