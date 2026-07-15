import * as x509 from '@peculiar/x509';
import { OID_CLIENT_AUTH, OID_SERVER_AUTH } from '../pki/certgen';
import { bytesToHex } from '../pki/hex';
import { parseNameConstraints } from '../pki/nameconstraints';
import { sanDnsNames } from '../pki/validate';
import type { LabCert, LabPki } from '../pki/types';
import { el } from './common';

const KU_NAMES: [number, string][] = [
  [x509.KeyUsageFlags.digitalSignature, 'digitalSignature'],
  [x509.KeyUsageFlags.nonRepudiation, 'nonRepudiation'],
  [x509.KeyUsageFlags.keyEncipherment, 'keyEncipherment'],
  [x509.KeyUsageFlags.dataEncipherment, 'dataEncipherment'],
  [x509.KeyUsageFlags.keyAgreement, 'keyAgreement'],
  [x509.KeyUsageFlags.keyCertSign, 'keyCertSign'],
  [x509.KeyUsageFlags.cRLSign, 'cRLSign'],
];

function ekuName(oid: string): string {
  if (oid === OID_SERVER_AUTH) return `serverAuth (${oid})`;
  if (oid === OID_CLIENT_AUTH) return `clientAuth (${oid})`;
  return oid;
}

/**
 * Every certificate in the lab, inspectable: parsed fields, decoded
 * extensions, the raw DER bytes, and a real signature verdict against every
 * candidate issuer key in the PKI.
 */
export function renderInspector(root: HTMLElement, pki: LabPki): void {
  root.append(
    el('p', { class: 'lede' }, [
      'Everything the validator judges is bytes you can read. Pick a certificate: its parsed fields, ' +
        'its extensions (where all the authority lives), its full DER encoding, and a live ECDSA ' +
        'verdict against every candidate issuer key in the lab.',
    ]),
  );

  const nav = el('nav', { class: 'inspect-nav', 'aria-label': 'Certificates' });
  const detail = el('div', { 'aria-live': 'polite' });
  const cols = el('div', { class: 'inspector-cols' }, [nav, detail]);
  root.append(cols);

  const groups: [string, LabCert[]][] = [
    ['Roots', pki.all.filter((c) => c.role === 'root')],
    ['Intermediates', pki.all.filter((c) => c.role === 'intermediate')],
    ['Leaves', pki.all.filter((c) => c.role === 'leaf')],
  ];
  const buttons = new Map<string, HTMLButtonElement>();
  for (const [title, certs] of groups) {
    nav.append(el('h3', {}, [title]));
    for (const c of certs) {
      const btn = el(
        'button',
        {
          type: 'button',
          'aria-pressed': 'false',
          onclick: () => void show(c),
        },
        [c.nickname],
      );
      buttons.set(c.id, btn);
      nav.append(btn);
    }
  }

  async function show(lab: LabCert): Promise<void> {
    for (const [id, b] of buttons) b.setAttribute('aria-pressed', id === lab.id ? 'true' : 'false');
    const cert = lab.cert;
    detail.replaceChildren(el('h3', {}, [lab.nickname]));

    // Live signature verdicts against every candidate issuer key. Real
    // WebCrypto ECDSA over the real DER TBS — the same call the validator makes.
    const claims = pki.all.filter((c) => c.cert.subject === cert.issuer);
    const sigLines: string[] = [];
    for (const cand of claims) {
      const selfNote = cand.id === lab.id ? ' (itself)' : '';
      const ok = await cert.verify({ publicKey: cand.cert.publicKey, signatureOnly: true });
      sigLines.push(
        `${ok ? '✓ verifies' : '✗ does not verify'} under the key of "${cand.nickname}"${selfNote}`,
      );
    }
    if (claims.length === 0) sigLines.push('no certificate in the lab carries the issuer DN this cert names');

    const rows: [string, string][] = [
      ['Subject', cert.subject],
      ['Issuer', cert.issuer],
      ['Serial number', cert.serialNumber],
      ['Public key', 'ECDSA on P-256 (id-ecPublicKey, prime256v1)'],
      ['Signature algorithm', 'ecdsa-with-SHA256'],
      [
        'Validity',
        `${cert.notBefore.toISOString().slice(0, 10)} → ${cert.notAfter.toISOString().slice(0, 10)}` +
          (Date.now() > cert.notAfter.getTime() ? '  (EXPIRED)' : ''),
      ],
      ['Signature verdict (live ECDSA)', sigLines.join('; ')],
    ];

    const san = sanDnsNames(cert);
    if (san.length > 0) rows.push(['subjectAltName (dNSName)', san.join(', ')]);

    const bc = cert.getExtension(x509.BasicConstraintsExtension);
    rows.push([
      'basicConstraints',
      bc
        ? `CA:${bc.ca ? 'TRUE' : 'FALSE'}${bc.pathLength !== undefined ? `, pathLenConstraint=${bc.pathLength}` : ''} (critical)`
        : 'absent — not a CA',
    ]);

    const ku = cert.getExtension(x509.KeyUsagesExtension);
    rows.push([
      'keyUsage',
      ku ? KU_NAMES.filter(([f]) => ku.usages & f).map(([, n]) => n).join(', ') || '(none set)' : 'absent',
    ]);

    const eku = cert.getExtension(x509.ExtendedKeyUsageExtension);
    if (eku) rows.push(['extendedKeyUsage', eku.usages.map((u) => ekuName(String(u))).join(', ')]);

    const nc = parseNameConstraints(cert);
    if (nc) {
      const parts: string[] = [];
      if (nc.permittedDns.length) parts.push(`permitted dNSName: ${nc.permittedDns.join(', ')}`);
      if (nc.excludedDns.length) parts.push(`excluded dNSName: ${nc.excludedDns.join(', ')}`);
      rows.push(['nameConstraints (critical)', parts.join('; ')]);
    }

    const ski = cert.getExtension(x509.SubjectKeyIdentifierExtension);
    if (ski) rows.push(['subjectKeyIdentifier', ski.keyId]);
    const aki = cert.getExtension(x509.AuthorityKeyIdentifierExtension);
    if (aki?.keyId) rows.push(['authorityKeyIdentifier', aki.keyId]);

    const table = el('table', { class: 'kv-table' });
    const tbody = el('tbody');
    for (const [k, v] of rows) {
      tbody.append(el('tr', {}, [el('th', { scope: 'row', text: k }), el('td', { text: v })]));
    }
    table.append(tbody);
    detail.append(table);

    const der = bytesToHex(cert.rawData).replace(/(..)/g, '$1 ').trim();
    detail.append(
      el('h3', {}, [`DER encoding (${cert.rawData.byteLength} bytes — what actually gets signed and parsed)`]),
      el(
        'div',
        {
          class: 'der-dump',
          tabindex: '0',
          role: 'region',
          'aria-label': `DER bytes of ${lab.nickname}`,
        },
        [der],
      ),
    );
  }

  void show(pki.byId('leaf-www'));
}
