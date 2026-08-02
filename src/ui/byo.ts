import { buildAndValidate } from '../pki/build';
import { parsePemCertificates } from '../pki/pem';
import { validatePath } from '../pki/validate';
import type { LabPki, ValidateOptions } from '../pki/types';
import { checkTable, chipRow, el } from './common';
import { glossaryBox } from './glossary';

/**
 * Bring-your-own-chain: paste real PEM certificates and run the same
 * builder, validator, and verdict-separated rendering the lab uses.
 * Everything stays in this tab — nothing is uploaded, fetched, or stored.
 * Revocation is honestly reported as NOT EVALUATED (no fixture, no network).
 */
export function renderByo(root: HTMLElement, pki: LabPki): void {
  root.append(
    el('p', { class: 'lede' }, [
      'The validator you just played against is not locked to the lab’s certificates. Paste any PEM ' +
        'chain — from a real server, `openssl s_client -showcerts`, or a file — plus the anchors you ' +
        'choose to trust, and run the same RFC 5280 checks. Everything happens in this tab: nothing is ' +
        'uploaded, fetched, or persisted.',
    ]),
    glossaryBox(),
  );

  const chainInput = el('textarea', {
    id: 'byo-chain',
    rows: '8',
    spellcheck: 'false',
    placeholder: '-----BEGIN CERTIFICATE-----\n…leaf first, then intermediates…\n-----END CERTIFICATE-----',
  });
  const trustInput = el('textarea', {
    id: 'byo-trust',
    rows: '5',
    spellcheck: 'false',
    placeholder: '-----BEGIN CERTIFICATE-----\n…the root(s) YOU choose to trust…\n-----END CERTIFICATE-----',
  });
  const hostInput = el('input', {
    id: 'byo-host',
    type: 'text',
    placeholder: 'www.example.test (leave empty to skip the hostname check)',
  });
  const ekuSelect = el('select', { id: 'byo-eku' });
  ekuSelect.append(
    el('option', { value: 'serverAuth', text: 'serverAuth (TLS server)' }),
    el('option', { value: 'clientAuth', text: 'clientAuth (TLS client)' }),
    el('option', { value: '', text: 'no EKU requirement' }),
  );

  const demoBtn = el('button', { type: 'button' }, ['Load the lab’s own chain as an example']);
  const validateBtn = el('button', { type: 'button', class: 'primary' }, ['▶ Validate my chain']);
  const results = el('div', { role: 'status', 'aria-live': 'polite' });

  root.append(
    el('div', { class: 'byo-grid' }, [
      el('div', {}, [
        el('label', { for: 'byo-chain' }, [
          'Certificate chain (PEM) — the first block is treated as the leaf; the rest are the bag',
        ]),
        chainInput,
      ]),
      el('div', {}, [
        el('label', { for: 'byo-trust' }, ['Trust anchors (PEM) — what your verifier is configured to trust']),
        trustInput,
      ]),
    ]),
    el('div', { class: 'controls' }, [
      el('label', { for: 'byo-host' }, ['Host:']),
      hostInput,
      el('label', { for: 'byo-eku' }, ['Validate for:']),
      ekuSelect,
    ]),
    el('div', { class: 'controls' }, [validateBtn, demoBtn]),
    results,
  );

  demoBtn.addEventListener('click', () => {
    chainInput.value =
      pki.byId('leaf-www').cert.toString('pem') + '\n' + pki.byId('issuing-b').cert.toString('pem');
    trustInput.value = pki.byId('root-y').cert.toString('pem');
    hostInput.value = 'www.example.test';
    ekuSelect.value = 'serverAuth';
    results.replaceChildren(
      el('p', { class: 'lede' }, [
        'Loaded this session’s leaf, intermediate B, and Root Y as PEM — the same bytes the panels above ' +
          'use. Edit anything (flip one base64 character and watch the signature check fail) and validate.',
      ]),
    );
  });

  validateBtn.addEventListener('click', () => void run());

  async function run(): Promise<void> {
    results.replaceChildren();
    let chain, anchors;
    try {
      chain = parsePemCertificates(chainInput.value, 'user');
      anchors = parsePemCertificates(trustInput.value, 'anchor');
    } catch (err) {
      results.append(
        el('div', { class: 'alarm' }, [
          el('p', { class: 'alarm-title' }, ['✗ Input rejected (fail closed).']),
          el('p', {}, [err instanceof Error ? err.message : String(err)]),
        ]),
      );
      return;
    }

    const opts: ValidateOptions = {
      trustStore: anchors,
      host: hostInput.value.trim() || null,
      requiredEku: (ekuSelect.value || null) as ValidateOptions['requiredEku'],
      revocationSource: 'not-evaluated',
    };

    const outcome = await buildAndValidate({
      leaf: chain[0],
      bag: chain.slice(1),
      validateOpts: opts,
      backtrack: true,
    });

    const result = outcome.found ? outcome.result! : await validatePath(chain, opts);
    const pathLine = (outcome.found ? outcome.path! : chain).map((c) => c.nickname).join(' → ');

    results.append(
      el('p', {}, [
        el('strong', {}, [outcome.found ? 'Path found by the backtracking builder: ' : 'No valid path found. ']),
        outcome.found
          ? pathLine
          : `Below: the RFC 5280 checklist for the chain exactly as pasted (${pathLine}).`,
      ]),
      chipRow(result),
      el('p', { class: 'lede' }, [
        'Revocation was NOT evaluated: imported chains have no status source here and this lab performs ' +
          'no CRL/OCSP fetch. An otherwise-valid chain therefore receives UNKNOWN, not ACCEPT.',
      ]),
      checkTable(result, 'Validator checklist for the imported chain'),
    );
  }
}
