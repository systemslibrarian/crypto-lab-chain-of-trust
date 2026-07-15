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
  const accept = result.verdict === 'ACCEPT';
  return el(
    'span',
    { class: `chip ${accept ? 'chip-accept' : 'chip-reject'}` },
    [accept ? 'Verdict: ACCEPT ✓' : 'Verdict: REJECT ✗'],
  );
}

export function chipRow(result: ValidationResult): HTMLElement {
  return el('div', { class: 'chip-row' }, [signatureFactChip(result), verdictChip(result)]);
}

/** Full RFC 5280 check table: every check reported independently. Failed
 * checks with an attributed certificate get a jump-to-evidence button. */
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
  return table;
}

function checkRow(c: CheckResult, inspect?: InspectFn): HTMLElement {
  const detailCell = el('td', { class: 'check-detail' }, [
    el('details', {}, [el('summary', { text: c.ok ? 'why it passes' : 'why it fails' }), c.detail]),
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
    el('td', { class: c.ok ? 'status-pass' : 'status-fail' }, [c.ok ? '✓ pass' : '✗ FAIL']),
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
