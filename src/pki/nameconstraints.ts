import { AsnConvert } from '@peculiar/asn1-schema';
import {
  GeneralName as AsnGeneralName,
  GeneralSubtree,
  GeneralSubtrees,
  NameConstraints,
} from '@peculiar/asn1-x509';
import * as x509 from '@peculiar/x509';

export const NAME_CONSTRAINTS_OID = '2.5.29.30';

/**
 * Build a real, DER-encoded nameConstraints extension (RFC 5280 §4.2.1.10)
 * limited to dNSName subtrees — the only name form this lab constrains.
 */
export function makeNameConstraintsExtension(opts: {
  permittedDns?: string[];
  excludedDns?: string[];
}): x509.Extension {
  const subtrees = (names?: string[]) =>
    names && names.length > 0
      ? new GeneralSubtrees(
          names.map((d) => new GeneralSubtree({ base: new AsnGeneralName({ dNSName: d }) })),
        )
      : undefined;
  const nc = new NameConstraints({
    permittedSubtrees: subtrees(opts.permittedDns),
    excludedSubtrees: subtrees(opts.excludedDns),
  });
  // nameConstraints MUST be critical (RFC 5280 §4.2.1.10)
  return new x509.Extension(NAME_CONSTRAINTS_OID, true, AsnConvert.serialize(nc));
}

export interface ParsedNameConstraints {
  permittedDns: string[];
  excludedDns: string[];
}

export function parseNameConstraints(cert: x509.X509Certificate): ParsedNameConstraints | null {
  const ext = cert.getExtension<x509.Extension>(NAME_CONSTRAINTS_OID);
  if (!ext) return null;
  const nc = AsnConvert.parse(ext.value, NameConstraints);
  const dns = (subtrees?: GeneralSubtrees): string[] =>
    (subtrees ?? []).map((s) => s.base.dNSName).filter((d): d is string => typeof d === 'string');
  return { permittedDns: dns(nc.permittedSubtrees), excludedDns: dns(nc.excludedSubtrees) };
}

/**
 * RFC 5280 §4.2.1.10 dNSName subtree membership: a DNS name is within the
 * subtree if it equals the base or can be formed by prepending labels to it.
 */
export function dnsNameInSubtree(name: string, base: string): boolean {
  const n = name.trim().toLowerCase().replace(/\.$/, '');
  const b = base.trim().toLowerCase().replace(/^\.+/, '').replace(/\.$/, '');
  if (b === '') return true; // empty base constrains nothing / permits everything
  return n === b || n.endsWith('.' + b);
}
