import { el } from './common';

/**
 * Just-in-time jargon translation. Rendered as a collapsible box inside the
 * panels where the terms first bite (puzzle, inspector, bring-your-own-chain)
 * — not a separate wall of docs.
 */
const GLOSSARY: [string, string][] = [
  [
    'Leaf / end-entity',
    'The certificate at the bottom of the chain — the one naming the server (or client) you are actually talking to. It certifies a key, never other certificates.',
  ],
  [
    'Intermediate',
    'A certificate authority certificate between the leaf and a root. It exists so roots can stay offline; its authority is delegated, and every constraint on it limits everything below it.',
  ],
  [
    'Trust anchor / root',
    'A certificate your verifier was CONFIGURED to trust — shipped with your OS or browser. Nothing in its bytes makes it a root; membership in your trust store does.',
  ],
  [
    'Cross-sign',
    'The same CA key certified by two different parents: one subject, one public key, two certificates. It is how new roots bootstrap trust — and why more than one chain can exist for one leaf.',
  ],
  [
    'SAN (subjectAltName)',
    'The extension that lists which DNS names a certificate is valid for. This is where hostname matching happens; the human-readable CN field is a deprecated relic.',
  ],
  [
    'CN (common name)',
    'A free-text name inside the subject. Old verifiers fell back to it for hostname checks; RFC 9525 and modern browsers ignore it when judging identity.',
  ],
  [
    'basicConstraints',
    'The extension that says whether a certificate is a CA at all (CA:TRUE/FALSE) and, via pathLenConstraint, how many further CAs may sit below it.',
  ],
  [
    'keyUsage / keyCertSign',
    'Bit flags saying what operations a key was certified for. A CA must have keyCertSign; without it, even a CA:TRUE certificate may not sign other certificates.',
  ],
  [
    'EKU (extendedKeyUsage)',
    'What PURPOSE the certificate serves: serverAuth (a TLS server), clientAuth (a TLS client), and others. A key certified for one job presented for another fails this check.',
  ],
  [
    'nameConstraints',
    'A fence on an intermediate: DNS subtrees it is permitted (or forbidden) to issue names in. Delegated authority stays inside its territory — or the path fails.',
  ],
  [
    'Revocation (CRL / OCSP)',
    'The issuer taking a certificate back before it expires. The certificate bytes do not change — the status lives outside the chain, in a list (CRL) or a query (OCSP) your verifier must consult.',
  ],
  [
    'DER',
    'The exact binary encoding of a certificate — the bytes that get signed and parsed. Everything the validator judges is readable in the inspector’s DER dump.',
  ],
];

export function glossaryBox(): HTMLElement {
  return el('details', { class: 'scope-note' }, [
    el('summary', { text: 'Jargon, translated (plain-language glossary)' }),
    el(
      'dl',
      { class: 'glossary' },
      GLOSSARY.flatMap(([term, def]) => [
        el('dt', { text: term }),
        el('dd', { text: def }),
      ]),
    ),
  ]);
}
