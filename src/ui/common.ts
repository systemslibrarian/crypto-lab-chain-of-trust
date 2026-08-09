import type { CheckId, CheckResult, ValidationResult } from '../pki/types';

/** Callback that opens a certificate in the inspector, highlighting the
 * field(s) that are evidence for a given check. */
export type InspectFn = (certId: string, evidence: CheckId) => void;

type Attrs = Record<string, string | boolean | ((ev: Event) => void)>;

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  children: (Node | string)[] = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (typeof v === 'function') node.addEventListener(k.replace(/^on/, ''), v);
    else if (typeof v === 'boolean') {
      if (v) node.setAttribute(k, '');
    } else if (k === 'text') node.textContent = v;
    else node.setAttribute(k, v);
  }
  for (const c of children) node.append(c);
  return node;
}

/**
 * VERDICT SEPARATION — the heart of the lab's visual semantics.
 * The cryptographic result and the security verdict are rendered as two
 * separate chips, never merged. The signature chip is deliberately
 * monochrome (a fact, not a judgment); only the verdict chip carries
 * accept/reject color, because color tracks system integrity here.
 */
export function signatureFactChip(result: ValidationResult): HTMLElement {
  const sigChecks = result.checks.filter((c) => c.id === 'signature');
  const n = sigChecks.length;
  const text =
    n === 0
      ? 'Signature: no links to check (single certificate, not self-signed)'
      : result.signatureChainOk
        ? `Signature: valid ✓ (${n === 1 ? '1 real ECDSA verification' : `all ${n} real ECDSA verifications`} pass)`
        : 'Signature: INVALID ✗ (a link fails real ECDSA verification)';
  return el('span', { class: 'chip chip-fact' }, [text]);
}

export function verdictChip(result: ValidationResult): HTMLElement {
  const presentation =
    result.verdict === 'ACCEPT'
      ? { className: 'chip-accept', text: 'Verdict: ACCEPT ✓' }
      : result.verdict === 'REJECT'
        ? { className: 'chip-reject', text: 'Verdict: REJECT ✗' }
        : { className: 'chip-unknown', text: 'Verdict: UNKNOWN — revocation not evaluated' };
  return el(
    'span',
    { class: `chip ${presentation.className}` },
    [presentation.text],
  );
}

export function chipRow(result: ValidationResult): HTMLElement {
  return el('div', { class: 'chip-row' }, [signatureFactChip(result), verdictChip(result)]);
}

/**
 * Wrap a node in a horizontally scrolling region that is a keyboard focus
 * target exactly while it is actually scrolling.
 *
 * A scrolling box holding nothing focusable is unreachable by keyboard (WCAG
 * 2.1.1), and the usual fix — a static `tabindex="0"` — leaves a tab stop that
 * does nothing on every viewport wide enough not to scroll. Since whether the
 * box scrolls is a function of the viewport, so is whether it should be a focus
 * target; a ResizeObserver is what keeps the two in step across a rotation or a
 * window drag. Both the box and its content are observed, because the content
 * can change size (a check table grows a row) without the box doing so.
 */
export function scrollRegion(label: string, child: HTMLElement): HTMLElement {
  const box = el('div', { class: 'scroll-region', role: 'region', 'aria-label': label }, [child]);
  const sync = (): void => {
    if (box.scrollWidth > box.clientWidth + 1) box.setAttribute('tabindex', '0');
    else box.removeAttribute('tabindex');
  };
  const ro = new ResizeObserver(sync);
  ro.observe(box);
  ro.observe(child);
  return box;
}

/** Full RFC 5280 check table: every check reported independently. Failed
 * checks with an attributed certificate get a jump-to-evidence button.
 *
 * Returned inside a `scrollRegion`: four columns of verdict, check name, kind
 * and a paragraph of detail have a min-content width of ~385px and cannot
 * reflow below it — forcing them to would break "nameConstraints" across two
 * lines — so on a phone the table scrolls sideways inside its own box rather
 * than scrolling the document (WCAG 1.4.10). The caption doubles as the
 * region's accessible name so a keyboard user landing there is told which
 * checklist they are in. */
export function checkTable(result: ValidationResult, caption: string, inspect?: InspectFn): HTMLElement {
  const table = el('table', { class: 'check-table' });
  table.append(el('caption', { class: 'sr-caption', text: caption }));
  const thead = el('thead', {}, [
    el('tr', {}, [
      el('th', { scope: 'col', text: 'Result' }),
      el('th', { scope: 'col', text: 'Check' }),
      el('th', { scope: 'col', text: 'Kind' }),
      el('th', { scope: 'col', text: 'Detail' }),
    ]),
  ]);
  const tbody = el('tbody');
  for (const c of result.checks) {
    tbody.append(checkRow(c, inspect));
  }
  table.append(thead, tbody);
  return scrollRegion(caption, table);
}

function checkRow(c: CheckResult, inspect?: InspectFn): HTMLElement {
  const evaluated = c.evaluated !== false;
  const detailCell = el('td', { class: 'check-detail' }, [
    el('details', {}, [
      el('summary', { text: !evaluated ? 'why it is unknown' : c.ok ? 'why it passes' : 'why it fails' }),
      c.detail,
    ]),
  ]);
  if (!c.ok && c.certId && inspect) {
    const certId = c.certId;
    detailCell.append(
      el(
        'button',
        {
          type: 'button',
          class: 'evidence-btn',
          'aria-label': `Open the evidence for "${c.label}" in the certificate inspector`,
          onclick: () => inspect(certId, c.id),
        },
        ['Show evidence in inspector ↓'],
      ),
    );
  }
  return el('tr', {}, [
    el(
      'td',
      { class: !evaluated ? 'status-unknown' : c.ok ? 'status-pass' : 'status-fail' },
      [!evaluated ? '— UNKNOWN' : c.ok ? '✓ pass' : '✗ FAIL'],
    ),
    el('td', {}, [c.label, el('div', { class: 'rfc-ref', text: c.rfc })]),
    el('td', {}, [
      el('span', {
        class: `badge ${c.cryptographic ? 'badge-crypto' : ''}`,
        text: c.cryptographic ? 'crypto' : 'policy',
      }),
    ]),
    detailCell,
  ]);
}

export const CHECK_NAMES: Record<string, string> = {
  'trust-anchor': 'Trust anchor (not in my store)',
  signature: 'Signature (cryptographic failure)',
  validity: 'Validity dates (something expired / not yet valid)',
  'basic-constraints': 'basicConstraints (issuer is not a CA)',
  'path-len': 'pathLenConstraint (chain too deep)',
  'key-usage': 'keyUsage (issuer lacks keyCertSign)',
  'name-constraints': 'nameConstraints (name outside permitted subtree)',
  eku: 'extendedKeyUsage (certified for the wrong purpose)',
  revocation: 'Revocation (a certificate is revoked)',
  hostname: 'Hostname (SAN does not match the host)',
};
