import { beforeAll, describe, expect, it } from 'vitest';
import { generateLabPki } from './certgen';
import { parsePemCertificates } from './pem';
import { validatePath } from './validate';
import type { LabPki } from './types';

let pki: LabPki;
beforeAll(async () => {
  pki = await generateLabPki();
}, 30_000);

describe('parsePemCertificates (bring-your-own-chain input)', () => {
  it('round-trips a single lab certificate through PEM', () => {
    const pem = pki.byId('leaf-www').cert.toString('pem');
    const [parsed] = parsePemCertificates(pem, 'user');
    expect(parsed.nickname).toBe('www.example.test');
    expect(parsed.role).toBe('leaf');
    expect(parsed.cert.serialNumber).toBe(pki.byId('leaf-www').cert.serialNumber);
  });

  it('parses multiple concatenated PEM blocks in order and classifies roles', () => {
    const text = ['leaf-www', 'issuing-b', 'root-y']
      .map((id) => pki.byId(id).cert.toString('pem'))
      .join('\n');
    const parsed = parsePemCertificates(text, 'user');
    expect(parsed.map((c) => c.role)).toEqual(['leaf', 'intermediate', 'root']);
    expect(parsed.map((c) => c.id)).toEqual(['user-0', 'user-1', 'user-2']);
  });

  it('fails closed on garbage, empty input, and corrupted base64', () => {
    expect(() => parsePemCertificates('hello world', 'user')).toThrow(/no .*BEGIN CERTIFICATE/);
    expect(() => parsePemCertificates('', 'user')).toThrow();
    const corrupt =
      '-----BEGIN CERTIFICATE-----\nAAAA!!!!not-base64####\n-----END CERTIFICATE-----';
    expect(() => parsePemCertificates(corrupt, 'user')).toThrow(/did not parse/);
  });

  it('an imported lab chain validates identically to the in-memory one', async () => {
    const reparsed = parsePemCertificates(
      ['leaf-www', 'issuing-b', 'root-y'].map((id) => pki.byId(id).cert.toString('pem')).join('\n'),
      'user',
    );
    const trust = parsePemCertificates(pki.byId('root-y').cert.toString('pem'), 'anchor');
    const result = await validatePath(reparsed, {
      trustStore: trust,
      host: 'www.example.test',
      requiredEku: 'serverAuth',
      revocationSource: 'not-evaluated',
    });
    expect(result.verdict).toBe('UNKNOWN');
    expect(result.signatureChainOk).toBe(true);
  });

  it('revocation is reported as NOT EVALUATED for imported chains, never as a clean pass', async () => {
    const reparsed = parsePemCertificates(
      ['leaf-www', 'issuing-b', 'root-y'].map((id) => pki.byId(id).cert.toString('pem')).join('\n'),
      'user',
    );
    const trust = parsePemCertificates(pki.byId('root-y').cert.toString('pem'), 'anchor');
    const result = await validatePath(reparsed, {
      trustStore: trust,
      revocationSource: 'not-evaluated',
    });
    const rev = result.checks.find((c) => c.id === 'revocation');
    expect(rev?.label).toContain('NOT EVALUATED');
    expect(rev?.evaluated).toBe(false);
    expect(rev?.detail).toContain('no CRL/OCSP network fetch');
    expect(result.verdict).toBe('UNKNOWN');
  });

  it('a real validation failure takes precedence over unknown revocation status', async () => {
    const reparsed = parsePemCertificates(
      ['leaf-www', 'issuing-b', 'root-y'].map((id) => pki.byId(id).cert.toString('pem')).join('\n'),
      'user',
    );
    const result = await validatePath(reparsed, {
      trustStore: [],
      revocationSource: 'not-evaluated',
    });
    expect(result.verdict).toBe('REJECT');
    expect(result.failures.some((check) => check.id === 'trust-anchor')).toBe(true);
  });
});
