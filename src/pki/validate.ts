import * as x509 from '@peculiar/x509';
import { OID_CLIENT_AUTH, OID_SERVER_AUTH } from './certgen';
import { equalBytes } from './hex';
import { matchHostname } from './hostname';
import { dnsNameInSubtree, parseNameConstraints } from './nameconstraints';
import type { CheckResult, LabCert, ValidateOptions, ValidationResult } from './types';

export function sanDnsNames(cert: x509.X509Certificate): string[] {
  const ext = cert.getExtension(x509.SubjectAlternativeNameExtension);
  if (!ext) return [];
  return ext.names.items.filter((n) => n.type === 'dns').map((n) => n.value);
}

export function subjectCn(cert: x509.X509Certificate): string | null {
  const fields = cert.subjectName.getField('CN');
  return fields.length > 0 ? fields[0] : null;
}

function isSelfIssued(cert: x509.X509Certificate): boolean {
  return cert.subject === cert.issuer;
}

function fmtDate(d: Date): string {
  return d.toISOString().slice(0, 10);
}

/**
 * Pure-crypto fact, one result per link: does each certificate's ECDSA
 * signature verify under the public key of the certificate above it?
 * The last certificate (the anchor candidate) is checked against its own key.
 * Every verification here is a real WebCrypto ECDSA P-256 operation over the
 * certificate's real DER TBS bytes.
 */
export async function checkSignatureChain(path: LabCert[]): Promise<CheckResult[]> {
  const checks: CheckResult[] = [];
  for (let i = 0; i < path.length; i++) {
    const child = path[i];
    const issuer = i + 1 < path.length ? path[i + 1] : null;
    if (issuer) {
      const namesChain = child.cert.issuer === issuer.cert.subject;
      const sigOk =
        namesChain &&
        (await child.cert.verify(
          { publicKey: issuer.cert.publicKey, signatureOnly: true },
        ));
      checks.push({
        id: 'signature',
        label: `Signature: ${child.nickname} ← ${issuer.nickname}`,
        certId: child.id,
        ok: sigOk,
        cryptographic: true,
        detail: !namesChain
          ? `Issuer DN of "${child.nickname}" (${child.cert.issuer}) does not match the subject DN of ` +
            `"${issuer.nickname}" (${issuer.cert.subject}) — the certificates do not chain by name.`
          : sigOk
            ? `ECDSA P-256 signature over the DER TBSCertificate verifies under the public key of "${issuer.nickname}".`
            : `ECDSA P-256 signature does NOT verify under the public key of "${issuer.nickname}".`,
        rfc: 'RFC 5280 §6.1.3(a)(1)',
      });
    } else if (child.cert.subject === child.cert.issuer) {
      // Top of the path claims to be self-signed — check that claim. A top
      // cert that names an absent issuer is not a crypto failure; the missing
      // anchor is the trust-anchor check's finding, so no entry is emitted.
      const selfOk = await child.cert.verify({ signatureOnly: true });
      checks.push({
        id: 'signature',
        label: `Signature: ${child.nickname} (self-signed)`,
        certId: child.id,
        ok: selfOk,
        cryptographic: true,
        detail: selfOk
          ? `Verifies under its own key — a statement anyone can produce about any key. ` +
            `Trust in an anchor comes from the trust store, never from this signature.`
          : `Does not even verify under its own key.`,
        rfc: 'RFC 5280 §6.1.1(d) (anchor trust is an input, not a signature)',
      });
    }
  }
  return checks;
}

/**
 * RFC 5280 §6 certification path validation (the subset this lab teaches),
 * plus RFC 6125/9525 server identity and a fixture-fed revocation status.
 *
 * `path` is ordered leaf-first: [leaf, intermediate…, anchor candidate].
 * Every check runs and is reported independently; the verdict is ACCEPT only
 * if all of them pass. Exactly one check ('signature') is cryptographic.
 */
export async function validatePath(path: LabCert[], opts: ValidateOptions): Promise<ValidationResult> {
  if (path.length === 0) throw new Error('validatePath: empty path');
  const at = opts.at ?? new Date();
  const checks: CheckResult[] = [];
  const leaf = path[0];
  const anchor = path[path.length - 1];
  const chain = [...path].reverse(); // anchor first, leaf last

  // 1. Trust anchor — configuration, not cryptography.
  const anchored = opts.trustStore.some((t) => equalBytes(t.cert.rawData, anchor.cert.rawData));
  checks.push({
    id: 'trust-anchor',
    label: 'Trust anchor',
    certId: anchor.id,
    ok: anchored,
    cryptographic: false,
    detail: anchored
      ? `The path terminates at "${anchor.nickname}", which is in the trust store. That membership is ` +
        `pure configuration — the same bytes under a different store are untrusted.`
      : path.length === 1
        ? `"${anchor.nickname}" vouches only for itself, and it is not in the trust store. Its self-signature ` +
          `is real ECDSA that anyone can produce for any key — being your own root convinces nobody else.`
        : `The path ends at "${anchor.nickname}", which is not in the trust store, so nothing anchors it.`,
    rfc: 'RFC 5280 §6.1.1(d)',
  });

  // 2. Signature chain — the one cryptographic column.
  const sigChecks = await checkSignatureChain(path);
  checks.push(...sigChecks);
  const signatureChainOk = sigChecks.every((c) => c.ok);

  // 3. Validity window, every certificate in the path.
  const expiredList = path.filter((c) => at < c.cert.notBefore || at > c.cert.notAfter);
  const firstExpired = expiredList[0] ?? null;
  checks.push({
    id: 'validity',
    label: 'Validity window',
    certId: firstExpired?.id ?? null,
    ok: expiredList.length === 0,
    cryptographic: false,
    detail:
      expiredList.length === 0
        ? `Every certificate in the path is within its [notBefore, notAfter] window at ${fmtDate(at)}.`
        : expiredList
            .map(
              (c) =>
                `"${c.nickname}" is outside its validity window (${fmtDate(c.cert.notBefore)} → ` +
                `${fmtDate(c.cert.notAfter)}) at ${fmtDate(at)}. Expiry does not degrade the mathematics — ` +
                `the signature still verifies — it withdraws the issuer's claim.`,
            )
            .join(' '),
    rfc: 'RFC 5280 §6.1.3(a)(2)',
  });

  // 4. basicConstraints — every cert that issued another must be a CA.
  const issuers = path.slice(1); // path[i+1] issued path[i]
  const bcFailures: string[] = [];
  let bcFailCert: string | null = null;
  for (const issuer of issuers) {
    const bc = issuer.cert.getExtension(x509.BasicConstraintsExtension);
    if (!bc) {
      bcFailures.push(
        `"${issuer.nickname}" has no basicConstraints extension, so it is not a CA, yet it issued a ` +
        `certificate in this path.`,
      );
      bcFailCert ??= issuer.id;
    } else if (!bc.ca) {
      bcFailures.push(
        `"${issuer.nickname}" carries basicConstraints CA:FALSE — an end-entity certificate. Its key can ` +
        `produce a flawless ECDSA signature over anything, including another certificate; CA:FALSE is the ` +
        `field that says such a signature confers no authority.`,
      );
      bcFailCert ??= issuer.id;
    }
  }
  checks.push({
    id: 'basic-constraints',
    label: 'basicConstraints (CA authority)',
    certId: bcFailCert,
    ok: bcFailures.length === 0,
    cryptographic: false,
    detail:
      bcFailures.length === 0
        ? 'Every issuing certificate in the path asserts basicConstraints CA:TRUE.'
        : bcFailures.join(' '),
    rfc: 'RFC 5280 §6.1.4(k)',
  });

  // 5. keyUsage — issuing certs with a keyUsage extension must assert keyCertSign.
  const kuFailures: string[] = [];
  let kuFailCert: string | null = null;
  for (const issuer of issuers) {
    const ku = issuer.cert.getExtension(x509.KeyUsagesExtension);
    if (ku && !(ku.usages & x509.KeyUsageFlags.keyCertSign)) {
      kuFailures.push(
        `"${issuer.nickname}" has a keyUsage extension without keyCertSign — its issuer authorized this key ` +
        `for other operations, not for signing certificates.`,
      );
      kuFailCert ??= issuer.id;
    }
  }
  checks.push({
    id: 'key-usage',
    label: 'keyUsage (keyCertSign)',
    certId: kuFailCert,
    ok: kuFailures.length === 0,
    cryptographic: false,
    detail:
      kuFailures.length === 0
        ? 'Every issuing certificate with a keyUsage extension asserts keyCertSign.'
        : kuFailures.join(' '),
    rfc: 'RFC 5280 §6.1.4(n)',
  });

  // 6. pathLenConstraint — walk anchor → leaf, decrementing.
  let maxPathLen = Number.POSITIVE_INFINITY;
  let plFail: { certId: string; detail: string } | null = null;
  const anchorBc = anchor.cert.getExtension(x509.BasicConstraintsExtension);
  if (anchorBc?.pathLength !== undefined) {
    // RFC 5280 §6.2 leaves anchor-extension processing to local policy; this
    // lab enforces it, as OpenSSL does.
    maxPathLen = anchorBc.pathLength;
  }
  for (let i = 1; i < chain.length - 1 && !plFail; i++) {
    const c = chain[i]; // an intermediate: it will issue chain[i+1]
    if (maxPathLen <= 0) {
      const setter = chain
        .slice(0, i)
        .reverse()
        .find((p) => p.cert.getExtension(x509.BasicConstraintsExtension)?.pathLength !== undefined);
      plFail = {
        certId: c.id,
        detail:
          `"${setter?.nickname ?? 'an ancestor'}" set pathLenConstraint=` +
          `${setter?.cert.getExtension(x509.BasicConstraintsExtension)?.pathLength}, allowing no further ` +
          `CA certificates beneath it — "${c.nickname}" is one level too deep. Every signature in this ` +
          `path is valid; the depth budget is what ran out.`,
      };
      break;
    }
    if (!isSelfIssued(c.cert)) maxPathLen -= 1;
    const bc = c.cert.getExtension(x509.BasicConstraintsExtension);
    if (bc?.pathLength !== undefined && bc.pathLength < maxPathLen) maxPathLen = bc.pathLength;
  }
  checks.push({
    id: 'path-len',
    label: 'pathLenConstraint (depth budget)',
    certId: plFail?.certId ?? null,
    ok: plFail === null,
    cryptographic: false,
    detail: plFail?.detail ?? 'No pathLenConstraint in the path is exceeded.',
    rfc: 'RFC 5280 §6.1.4(l),(m)',
  });

  // 7. nameConstraints — accumulate subtrees walking anchor → leaf; each
  // certificate is checked against constraints imposed ABOVE it.
  let permitted: { src: LabCert; bases: string[] } | null = null;
  const excluded: { src: LabCert; base: string }[] = [];
  let ncFail: { certId: string; detail: string } | null = null;
  for (const c of chain) {
    if (!ncFail) {
      const names = sanDnsNames(c.cert);
      for (const name of names) {
        const hitExcluded = excluded.find((e) => dnsNameInSubtree(name, e.base));
        if (hitExcluded) {
          ncFail = {
            certId: c.id,
            detail:
              `SAN dNSName "${name}" on "${c.nickname}" falls inside the excluded subtree ` +
              `"${hitExcluded.base}" imposed by "${hitExcluded.src.nickname}".`,
          };
          break;
        }
        if (permitted && !permitted.bases.some((b) => dnsNameInSubtree(name, b))) {
          ncFail = {
            certId: c.id,
            detail:
              `SAN dNSName "${name}" on "${c.nickname}" is outside every permitted subtree ` +
              `[${permitted.bases.join(', ')}] imposed by "${permitted.src.nickname}". The signature on ` +
              `"${c.nickname}" is valid ECDSA — the name is simply outside the territory this branch of ` +
              `the hierarchy was ever allowed to certify.`,
          };
          break;
        }
      }
    }
    const nc = parseNameConstraints(c.cert);
    if (nc) {
      if (nc.permittedDns.length > 0) {
        // Intersecting multiple permitted sets is out of the lab's scope; the
        // lab PKI carries at most one constrained CA per path.
        permitted = { src: c, bases: nc.permittedDns };
      }
      for (const base of nc.excludedDns) excluded.push({ src: c, base });
    }
  }
  checks.push({
    id: 'name-constraints',
    label: 'nameConstraints (territory)',
    certId: ncFail?.certId ?? null,
    ok: ncFail === null,
    cryptographic: false,
    detail:
      ncFail?.detail ??
      'No certificate in the path carries a name outside the dNSName subtrees imposed above it.',
    rfc: 'RFC 5280 §6.1.4(g), §4.2.1.10',
  });

  // 8. Extended key usage on the leaf (only when the scenario demands one).
  if (opts.requiredEku) {
    const requiredOid = opts.requiredEku === 'serverAuth' ? OID_SERVER_AUTH : OID_CLIENT_AUTH;
    const ekuExt = leaf.cert.getExtension(x509.ExtendedKeyUsageExtension);
    const ekuOk = !ekuExt || ekuExt.usages.map(String).includes(requiredOid);
    const listed = ekuExt ? ekuExt.usages.map((u) => ekuName(String(u))).join(', ') : null;
    checks.push({
      id: 'eku',
      label: `extendedKeyUsage (${opts.requiredEku})`,
      certId: leaf.id,
      ok: ekuOk,
      cryptographic: false,
      detail: !ekuExt
        ? `The leaf has no EKU extension, so RFC 5280 §4.2.1.12 imposes no restriction. (Real-world TLS ` +
          `verifiers following the CA/Browser Forum profile additionally require an explicit serverAuth.)`
        : ekuOk
          ? `The leaf's EKU [${listed}] includes ${opts.requiredEku}.`
          : `The leaf's EKU lists [${listed}] — this key was certified for ` +
            `${listed}, not for ${opts.requiredEku}. Using a client-authentication certificate to serve ` +
            `TLS is exactly the substitution EKU exists to stop; the signature cannot object.`,
      rfc: 'RFC 5280 §4.2.1.12',
    });
  }

  // 9. Revocation — a fixture-fed status lookup, deliberately not a signature.
  if (opts.revocationSource === 'not-evaluated') {
    checks.push({
      id: 'revocation',
      label: 'Revocation status — NOT EVALUATED',
      certId: null,
      ok: true,
      cryptographic: false,
      detail:
        `Imported chains have no status source in this lab: there is no fixture entry for them and the ` +
        `lab performs no CRL/OCSP network fetch, so revocation was NOT checked. A verdict of ACCEPT here ` +
        `means "valid except revocation unknown" — a production validator must consult CRL or OCSP ` +
        `before trusting this path.`,
      rfc: 'RFC 5280 §6.1.3(a)(3)',
    });
  } else {
    const revoked = opts.revoked ?? new Set<string>();
    const revokedHit = path.find((c) => revoked.has(c.id)) ?? null;
    checks.push({
      id: 'revocation',
      label: 'Revocation status (local fixture)',
      certId: revokedHit?.id ?? null,
      ok: revokedHit === null,
      cryptographic: false,
      detail: revokedHit
        ? `"${revokedHit.nickname}" is listed as REVOKED. Its certificate bytes are unchanged and its ` +
          `signature still verifies — revocation is a status you must go ask about (CRL/OCSP), not anything ` +
          `readable off the certificate. In this lab the status is a local fixture; no network fetch happens.`
        : `No certificate in the path is revoked in the lab's fixture. (Statuses are local fixtures — this ` +
          `lab performs no CRL/OCSP network fetch.)`,
      rfc: 'RFC 5280 §6.1.3(a)(3)',
    });
  }

  // 10. Server identity (RFC 6125/9525) — not part of RFC 5280 §6, but part of
  // "is this certificate valid for THIS connection".
  if (opts.host) {
    const m = matchHostname(opts.host, sanDnsNames(leaf.cert), subjectCn(leaf.cert));
    checks.push({
      id: 'hostname',
      label: `Server identity (host "${opts.host}")`,
      certId: leaf.id,
      ok: m.ok,
      cryptographic: false,
      detail: m.detail,
      rfc: 'RFC 6125 §6.4 / RFC 9525 (separate from RFC 5280 §6)',
    });
  }

  const failures = checks.filter((c) => !c.ok);
  return {
    checks,
    signatureChainOk,
    verdict: failures.length === 0 ? 'ACCEPT' : 'REJECT',
    failures,
  };
}

function ekuName(oid: string): string {
  switch (oid) {
    case OID_SERVER_AUTH: return 'serverAuth';
    case OID_CLIENT_AUTH: return 'clientAuth';
    default: return oid;
  }
}
