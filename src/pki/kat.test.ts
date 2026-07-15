import { describe, expect, it } from 'vitest';
import { bytesToHex, hexToBytes } from './hex';

/**
 * Known-answer tests for the two primitives everything in this lab rests on:
 * SHA-256 (FIPS 180-4) and ECDSA P-256 signature verification (FIPS 186-4
 * curve; vectors from RFC 6979 §A.2.5, which are standard P-256/SHA-256
 * signatures and thus valid verification KATs regardless of how k was made).
 * All operations run through the same WebCrypto used by the demo.
 */

const subtle = globalThis.crypto.subtle;

describe('SHA-256 KATs (FIPS 180-4)', () => {
  it('KAT 1: SHA-256("abc")', async () => {
    const digest = await subtle.digest('SHA-256', new TextEncoder().encode('abc'));
    expect(bytesToHex(digest)).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });

  it('KAT 2: SHA-256("")', async () => {
    const digest = await subtle.digest('SHA-256', new Uint8Array(0));
    expect(bytesToHex(digest)).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
  });
});

// RFC 6979 §A.2.5 — curve P-256, SHA-256, key:
const UX = '60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6';
const UY = '7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299';

const VECTORS = [
  {
    name: 'KAT 3: message "sample"',
    msg: 'sample',
    r: 'EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716',
    s: 'F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8',
  },
  {
    name: 'KAT 4: message "test"',
    msg: 'test',
    r: 'F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367',
    s: '019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083',
  },
];

async function importP256(xHex: string, yHex: string): Promise<CryptoKey> {
  const raw = new Uint8Array(65);
  raw[0] = 0x04;
  raw.set(hexToBytes(xHex), 1);
  raw.set(hexToBytes(yHex), 33);
  return subtle.importKey('raw', raw, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
}

function p1363(rHex: string, sHex: string): Uint8Array<ArrayBuffer> {
  const sig = new Uint8Array(64);
  sig.set(hexToBytes(rHex), 0);
  sig.set(hexToBytes(sHex), 32);
  return sig;
}

describe('ECDSA P-256 verification KATs (RFC 6979 §A.2.5 / FIPS 186-4)', () => {
  for (const v of VECTORS) {
    it(`${v.name} — signature verifies`, async () => {
      const key = await importP256(UX, UY);
      const ok = await subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        key,
        p1363(v.r, v.s),
        new TextEncoder().encode(v.msg),
      );
      expect(ok).toBe(true);
    });
  }

  it('KAT 5 (negative): one flipped bit in s must fail', async () => {
    const key = await importP256(UX, UY);
    const sig = p1363(VECTORS[0].r, VECTORS[0].s);
    sig[63] ^= 0x01;
    const ok = await subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      sig,
      new TextEncoder().encode('sample'),
    );
    expect(ok).toBe(false);
  });

  it('KAT 6 (negative): valid signature over the wrong message must fail', async () => {
    const key = await importP256(UX, UY);
    const ok = await subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      p1363(VECTORS[0].r, VECTORS[0].s),
      new TextEncoder().encode('sample.'),
    );
    expect(ok).toBe(false);
  });
});
