import { beforeAll, describe, expect, it } from 'vitest';
import * as x509 from '@peculiar/x509';
import { generateLabPki } from './certgen';
import { parseNameConstraints } from './nameconstraints';
import { sanDnsNames, subjectCn } from './validate';
import type { LabPki } from './types';

let pki: LabPki;
beforeAll(async () => {
  pki = await generateLabPki();
}, 30_000);

// child cert id → the id of the cert whose key actually signed it
const ISSUED_BY: Record<string, string> = {
  'root-x': 'root-x',
  'root-y': 'root-y',
  'issuing-a': 'root-x',
  'issuing-b': 'root-y',
  'leaf-www': 'issuing-b', // same key as issuing-a — either cross-sign verifies it
  'int-serverops': 'issuing-b',
  'leaf-rogue': 'int-serverops',
  'int-constrained': 'root-y',
  'int-deep': 'int-constrained',
  'leaf-deep': 'int-deep',
  'int-expired': 'root-y',
  'leaf-archive': 'int-expired',
  'leaf-shop': 'issuing-b',
  'leaf-device': 'issuing-b',
  'int-nosign': 'root-y',
  'leaf-iot': 'int-nosign',
  'int-retired': 'root-y',
  'leaf-legacy': 'int-retired',
  'leaf-standalone': 'leaf-standalone',
};

describe('generated lab PKI', () => {
  it('contains all 19 certificates', () => {
    expect(pki.all).toHaveLength(19);
    expect(new Set(pki.all.map((c) => c.id)).size).toBe(19);
  });

  it('every certificate re-parses from its own DER bytes', () => {
    for (const lab of pki.all) {
      const reparsed = new x509.X509Certificate(lab.cert.rawData);
      expect(reparsed.subject).toBe(lab.cert.subject);
      expect(reparsed.serialNumber).toBe(lab.cert.serialNumber);
    }
  });

  it('every certificate signature verifies under its real issuer key (WebCrypto ECDSA)', async () => {
    for (const [childId, issuerId] of Object.entries(ISSUED_BY)) {
      const child = pki.byId(childId);
      const issuer = pki.byId(issuerId);
      const ok = await child.cert.verify({
        publicKey: issuer.cert.publicKey,
        signatureOnly: true,
      });
      expect(ok, `${childId} should verify under ${issuerId}`).toBe(true);
    }
  });

  it('signatures do NOT verify under an unrelated key', async () => {
    const ok = await pki
      .byId('leaf-www')
      .cert.verify({ publicKey: pki.byId('root-x').cert.publicKey, signatureOnly: true });
    expect(ok).toBe(false);
  });

  it('cross-signs A and B share the subject and public key but are different certificates', () => {
    const a = pki.byId('issuing-a').cert;
    const b = pki.byId('issuing-b').cert;
    expect(a.subject).toBe(b.subject);
    expect(a.publicKey.toString('hex')).toBe(b.publicKey.toString('hex'));
    expect(a.issuer).not.toBe(b.issuer);
    expect(a.serialNumber).not.toBe(b.serialNumber);
  });

  it('cross-sign A carries the critical nameConstraints extension; B does not', () => {
    const nc = parseNameConstraints(pki.byId('issuing-a').cert);
    expect(nc).not.toBeNull();
    expect(nc!.permittedDns).toEqual(['internal.test']);
    expect(pki.byId('issuing-a').cert.getExtension('2.5.29.30')!.critical).toBe(true);
    expect(parseNameConstraints(pki.byId('issuing-b').cert)).toBeNull();
  });

  it('trap certs carry exactly the advertised defects', () => {
    const bc = (id: string) => pki.byId(id).cert.getExtension(x509.BasicConstraintsExtension);
    const ku = (id: string) => pki.byId(id).cert.getExtension(x509.KeyUsagesExtension);

    expect(bc('int-serverops')!.ca).toBe(false);
    expect(bc('int-constrained')!.ca).toBe(true);
    expect(bc('int-constrained')!.pathLength).toBe(0);
    expect(bc('int-nosign')!.ca).toBe(true);
    expect(ku('int-nosign')!.usages & x509.KeyUsageFlags.keyCertSign).toBe(0);

    const expired = pki.byId('int-expired').cert;
    expect(expired.notAfter.getTime()).toBeLessThan(Date.now());
    const archive = pki.byId('leaf-archive').cert;
    expect(archive.notAfter.getTime()).toBeGreaterThan(Date.now());

    expect(subjectCn(pki.byId('leaf-shop').cert)).toBe('www.example.test');
    expect(sanDnsNames(pki.byId('leaf-shop').cert)).toEqual(['shop.example.test']);

    const standalone = pki.byId('leaf-standalone').cert;
    expect(standalone.subject).toBe(standalone.issuer);
  });
});
