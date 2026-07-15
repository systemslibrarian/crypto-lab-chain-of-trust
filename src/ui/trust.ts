import { validatePath } from '../pki/validate';
import type { LabPki } from '../pki/types';
import { chipRow, el } from './common';

/**
 * Trust-store panel: the same two candidate paths, re-validated under every
 * combination of trusted roots. The certificate bytes and the ECDSA results
 * never change; the verdicts do. Trust is configuration.
 */
export function renderTrust(root: HTMLElement, pki: LabPki): void {
  root.append(
    el('p', { class: 'lede' }, [
      'Both cross-sign paths for www.example.test are shown below. Toggle which roots your client ' +
        'trusts and watch the verdicts — while the signature facts, computed from the same bytes by ' +
        'the same WebCrypto calls, never move. Nothing about a certificate makes it a root; ' +
        'being in the store does.',
    ]),
  );

  const trustX = el('input', { type: 'checkbox', id: 'trust-x', checked: true });
  const trustY = el('input', { type: 'checkbox', id: 'trust-y', checked: true });
  const fieldset = el('fieldset', { class: 'trust-controls' }, [
    el('legend', {}, ['My trust store']),
    el('label', { for: 'trust-x' }, [trustX, 'Trust Root X']),
    el('label', { for: 'trust-y' }, [trustY, 'Trust Root Y']),
  ]);
  root.append(fieldset);

  const grid = el('div', { class: 'trust-grid', role: 'status', 'aria-live': 'polite' });
  root.append(grid);

  const PATHS: { title: string; ids: string[]; line: string }[] = [
    {
      title: 'Path A (via cross-sign A)',
      ids: ['leaf-www', 'issuing-a', 'root-x'],
      line: 'leaf → Issuing CA (A) → Root X',
    },
    {
      title: 'Path B (via cross-sign B)',
      ids: ['leaf-www', 'issuing-b', 'root-y'],
      line: 'leaf → Issuing CA (B) → Root Y',
    },
  ];

  async function refresh(): Promise<void> {
    const store = [
      ...(trustX.checked ? [pki.byId('root-x')] : []),
      ...(trustY.checked ? [pki.byId('root-y')] : []),
    ];
    const cards: HTMLElement[] = [];
    for (const p of PATHS) {
      const result = await validatePath(
        p.ids.map((id) => pki.byId(id)),
        { trustStore: store, host: 'www.example.test', requiredEku: 'serverAuth' },
      );
      const failed = [...new Set(result.failures.map((f) => f.label))];
      cards.push(
        el('div', { class: 'trust-path' }, [
          el('h3', {}, [p.title]),
          el('p', { class: 'path-line', text: p.line }),
          chipRow(result),
          el('p', { class: 'lede' }, [
            result.verdict === 'ACCEPT'
              ? 'Every check passes under this store.'
              : `Fails: ${failed.join('; ')}.`,
          ]),
        ]),
      );
    }
    grid.replaceChildren(...cards);
  }

  trustX.addEventListener('change', () => void refresh());
  trustY.addEventListener('change', () => void refresh());
  void refresh();
}
