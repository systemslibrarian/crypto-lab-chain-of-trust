import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';

describe('X.509 initialization in a fresh process', () => {
  it('loads the shared SDK entry point before generating and independently verifying a real certificate', () => {
    const root = fileURLToPath(new URL('../../', import.meta.url));
    const scratch = mkdtempSync(join(tmpdir(), 'chain-x509-bootstrap-'));
    try {
      // The facade is also valid JavaScript. Execute its exact source bytes in
      // a cold process so Vitest's module cache or another test cannot supply
      // the missing initialization. This also works on supported Node 20.
      const facade = join(scratch, 'x509.mjs');
      writeFileSync(facade, readFileSync(new URL('./x509.ts', import.meta.url)));
      symlinkSync(join(root, 'node_modules'), join(scratch, 'node_modules'));
      const result = spawnSync(process.execPath, ['--input-type=module', '--eval', `
        import assert from 'node:assert/strict';
        import { KeyObject, X509Certificate as NativeCertificate } from 'node:crypto';
        assert.equal(typeof Reflect.getMetadata, 'undefined');
        const x509 = await import(${JSON.stringify(pathToFileURL(facade).href)});
        x509.cryptoProvider.set(globalThis.crypto);
        const algorithm = { name: 'ECDSA', namedCurve: 'P-256' };
        const keys = await crypto.subtle.generateKey(algorithm, true, ['sign', 'verify']);
        const other = await crypto.subtle.generateKey(algorithm, true, ['sign', 'verify']);
        const cert = await x509.X509CertificateGenerator.createSelfSigned({
          serialNumber: '01', name: 'CN=Cold Bootstrap',
          notBefore: new Date('2026-01-01T00:00:00Z'),
          notAfter: new Date('2036-01-01T00:00:00Z'),
          signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' }, keys,
          extensions: [new x509.BasicConstraintsExtension(true, 0, true)],
        }, crypto);
        assert.equal(cert.subject, 'CN=Cold Bootstrap');
        assert.equal(cert.getExtension(x509.BasicConstraintsExtension).pathLength, 0);
        assert.equal(await cert.verify({ publicKey: keys.publicKey, signatureOnly: true }, crypto), true);
        assert.equal(await cert.verify({ publicKey: other.publicKey, signatureOnly: true }, crypto), false);
        const native = new NativeCertificate(Buffer.from(cert.rawData));
        assert.equal(native.verify(KeyObject.from(keys.publicKey)), true);
        assert.equal(native.verify(KeyObject.from(other.publicKey)), false);
        console.log('cold X.509 bootstrap, real signature and wrong-key controls passed');
      `], { cwd: root, env: { ...process.env, NODE_OPTIONS: '' }, encoding: 'utf8', timeout: 30_000 });
      expect(result.error).toBeUndefined();
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout).toContain('cold X.509 bootstrap, real signature and wrong-key controls passed');
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  });
});
