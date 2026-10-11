import * as x509 from '@peculiar/x509';
import { describe, expect, it } from 'vitest';
import { validatePath } from './validate';
import type { LabCert } from './types';

// Real DER certificates and fresh, distinct WebCrypto keys: the rollover
// keeps the old CA's DN but is signed by its old key, not its own new key.
async function rolloverPath(opts: {
  budget: number;
  selfIssued?: boolean;
  rolloverBudget?: number;
  extraCa?: boolean;
}): Promise<LabCert[]> {
  const at = new Date('2026-01-15T00:00:00Z');
  let serial = 0;
  type Issuer = { name: string; keys: CryptoKeyPair };
  async function issue(id: string, name: string, role: LabCert['role'], issuer?: Issuer, pathLen?: number) {
    const keys = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'],
    );
    const signer = issuer ?? { name, keys };
    const cert = await x509.X509CertificateGenerator.create({
      serialNumber: (++serial).toString(16).padStart(2, '0'),
      subject: name,
      issuer: signer.name,
      notBefore: new Date(at.getTime() - 86_400_000),
      notAfter: new Date(at.getTime() + 86_400_000),
      signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
      publicKey: keys.publicKey,
      signingKey: signer.keys.privateKey,
      extensions: [
        new x509.BasicConstraintsExtension(role !== 'leaf', pathLen, true),
        new x509.KeyUsagesExtension(role === 'leaf'
          ? x509.KeyUsageFlags.digitalSignature : x509.KeyUsageFlags.keyCertSign, true),
        await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
        await x509.AuthorityKeyIdentifierExtension.create(signer.keys.publicKey),
      ],
    }, crypto);
    return { lab: { id, nickname: id, role, cert } as LabCert, issuer: { name, keys } };
  }
  const root = await issue('root', 'CN=Root', 'root');
  const oldCa = await issue('old-ca', 'CN=Rollover CA', 'intermediate', root.issuer, opts.budget);
  const rollover = await issue('rollover', opts.selfIssued === false ? 'CN=Different CA' : oldCa.issuer.name,
    'intermediate', oldCa.issuer, opts.rolloverBudget);
  const path = [root.lab, oldCa.lab, rollover.lab];
  let leafIssuer = rollover.issuer;
  if (opts.extraCa) {
    const extra = await issue('extra-ca', 'CN=Extra CA', 'intermediate', leafIssuer);
    path.push(extra.lab);
    leafIssuer = extra.issuer;
  }
  path.push((await issue('leaf', 'CN=Leaf', 'leaf', leafIssuer)).lab);
  return path.reverse();
}

describe('RFC 5280 §6.1.4(l),(m): self-issued CA rollover', () => {
  const cases = [
    { name: 'accepts rollover at zero remaining budget', opts: { budget: 0 }, failedCert: null },
    { name: 'rejects a non-self-issued intermediate at zero budget',
      opts: { budget: 0, selfIssued: false }, failedCert: 'rollover' },
    { name: 'does not replenish the budget after a self-issued rollover',
      opts: { budget: 0, extraCa: true }, failedCert: 'extra-ca' },
    { name: 'still applies pathLenConstraint on the self-issued certificate',
      opts: { budget: 1, rolloverBudget: 0, extraCa: true }, failedCert: 'extra-ca' },
    { name: 'does not consume a positive budget during rollover',
      opts: { budget: 1, rolloverBudget: 1, extraCa: true }, failedCert: null },
  ];
  for (const { name, opts, failedCert } of cases) {
    it(name, async () => {
      const path = await rolloverPath(opts);
      const rollover = path.find((c) => c.id === 'rollover')!;
      expect(rollover.cert.subject === rollover.cert.issuer).toBe(opts.selfIssued !== false);
      // Self-issued is not self-signed: the old key must vouch for the new key.
      expect(await rollover.cert.verify({ signatureOnly: true })).toBe(false);
      const result = await validatePath(path, {
        trustStore: [path[path.length - 1]], at: new Date('2026-01-15T00:00:00Z'),
      });
      expect(result.signatureChainOk).toBe(true);
      expect(result.verdict).toBe(failedCert === null ? 'ACCEPT' : 'REJECT');
      expect(result.failures.map((c) => ({ id: c.id, certId: c.certId }))).toEqual(
        failedCert === null ? [] : [{ id: 'path-len', certId: failedCert }],
      );
    });
  }
});
