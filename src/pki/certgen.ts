import * as x509 from '@peculiar/x509';
import { makeNameConstraintsExtension } from './nameconstraints';
import type { LabCert, LabPki } from './types';

// Real WebCrypto everywhere. In the browser this is window.crypto; in Node
// (Vitest) it is globalThis.crypto. @peculiar/x509 signs real DER TBS bytes
// with real ECDSA P-256 keys through this provider — nothing is simulated.
const webCrypto = globalThis.crypto;
x509.cryptoProvider.set(webCrypto);

const EC_GEN: EcKeyGenParams = { name: 'ECDSA', namedCurve: 'P-256' };
const SIGN_ALG = { name: 'ECDSA', hash: 'SHA-256' };

const DAY = 24 * 60 * 60 * 1000;

export const OID_SERVER_AUTH = '1.3.6.1.5.5.7.3.1';
export const OID_CLIENT_AUTH = '1.3.6.1.5.5.7.3.2';

async function genKeys(): Promise<CryptoKeyPair> {
  return webCrypto.subtle.generateKey(EC_GEN, true, ['sign', 'verify']);
}

interface CertSpec {
  id: string;
  nickname: string;
  role: LabCert['role'];
  subject: string;
  serial: string;
  notBefore: Date;
  notAfter: Date;
  san?: string[];
  basicConstraints?: { ca: boolean; pathLen?: number };
  keyUsages?: x509.KeyUsageFlags;
  eku?: string[];
  nameConstraints?: { permittedDns?: string[]; excludedDns?: string[] };
}

async function buildExtensions(
  spec: CertSpec,
  subjectKey: CryptoKey,
  issuerKey: CryptoKey,
): Promise<x509.Extension[]> {
  const exts: x509.Extension[] = [
    await x509.SubjectKeyIdentifierExtension.create(subjectKey, false, webCrypto),
    await x509.AuthorityKeyIdentifierExtension.create(issuerKey, false, webCrypto),
  ];
  if (spec.basicConstraints) {
    exts.push(
      new x509.BasicConstraintsExtension(spec.basicConstraints.ca, spec.basicConstraints.pathLen, true),
    );
  }
  if (spec.keyUsages !== undefined) {
    exts.push(new x509.KeyUsagesExtension(spec.keyUsages, true));
  }
  if (spec.eku) {
    exts.push(new x509.ExtendedKeyUsageExtension(spec.eku, false));
  }
  if (spec.san) {
    exts.push(
      new x509.SubjectAlternativeNameExtension(
        spec.san.map((value) => ({ type: 'dns' as const, value })),
        false,
      ),
    );
  }
  if (spec.nameConstraints) {
    exts.push(makeNameConstraintsExtension(spec.nameConstraints));
  }
  return exts;
}

async function makeCert(
  spec: CertSpec,
  subjectKeys: CryptoKeyPair,
  issuer: { subject: string; keys: CryptoKeyPair },
): Promise<LabCert> {
  const cert = await x509.X509CertificateGenerator.create(
    {
      serialNumber: spec.serial,
      subject: spec.subject,
      issuer: issuer.subject,
      notBefore: spec.notBefore,
      notAfter: spec.notAfter,
      signingAlgorithm: SIGN_ALG,
      publicKey: subjectKeys.publicKey,
      signingKey: issuer.keys.privateKey,
      extensions: await buildExtensions(spec, subjectKeys.publicKey, issuer.keys.publicKey),
    },
    webCrypto,
  );
  return { id: spec.id, nickname: spec.nickname, role: spec.role, cert };
}

const KU = x509.KeyUsageFlags;

/**
 * Generate the whole lab PKI: two roots, a cross-signed issuing CA (same
 * subject + same key, one certificate per parent root), and one deliberately
 * defective branch per trap in the ladder. Every certificate is real DER with
 * a real ECDSA P-256 signature; the defects are semantic (extensions, dates,
 * trust), never fake crypto. Fresh keys per session; nothing is persisted.
 */
export async function generateLabPki(now = new Date()): Promise<LabPki> {
  const nb = new Date(now.getTime() - 1 * DAY);
  const na = new Date(now.getTime() + 90 * DAY);
  const certs: LabCert[] = [];

  // --- Roots -------------------------------------------------------------
  const rootXKeys = await genKeys();
  const rootXName = 'CN=Lab Root X, O=Chain of Trust Lab';
  const rootYKeys = await genKeys();
  const rootYName = 'CN=Lab Root Y, O=Chain of Trust Lab';

  const rootX = await makeCert(
    {
      id: 'root-x', nickname: 'Root X', role: 'root', subject: rootXName, serial: '1001',
      notBefore: nb, notAfter: na,
      basicConstraints: { ca: true },
      keyUsages: KU.keyCertSign | KU.cRLSign,
    },
    rootXKeys,
    { subject: rootXName, keys: rootXKeys },
  );
  const rootY = await makeCert(
    {
      id: 'root-y', nickname: 'Root Y', role: 'root', subject: rootYName, serial: '1002',
      notBefore: nb, notAfter: na,
      basicConstraints: { ca: true },
      keyUsages: KU.keyCertSign | KU.cRLSign,
    },
    rootYKeys,
    { subject: rootYName, keys: rootYKeys },
  );
  certs.push(rootX, rootY);

  // --- Cross-signed issuing CA: ONE key pair, TWO certificates ------------
  // Cert A (signed by Root X) carries a nameConstraints extension permitting
  // only *.internal.test — Root X cross-signed the issuing CA for its
  // internal estate only. Cert B (signed by Root Y) is unconstrained.
  const issuingKeys = await genKeys();
  const issuingName = 'CN=Lab Issuing CA, O=Chain of Trust Lab';

  const issuingA = await makeCert(
    {
      id: 'issuing-a', nickname: 'Issuing CA (cross-sign A, via Root X)', role: 'intermediate',
      subject: issuingName, serial: '2001', notBefore: nb, notAfter: na,
      basicConstraints: { ca: true },
      keyUsages: KU.keyCertSign | KU.cRLSign,
      nameConstraints: { permittedDns: ['internal.test'] },
    },
    issuingKeys,
    { subject: rootXName, keys: rootXKeys },
  );
  const issuingB = await makeCert(
    {
      id: 'issuing-b', nickname: 'Issuing CA (cross-sign B, via Root Y)', role: 'intermediate',
      subject: issuingName, serial: '2002', notBefore: nb, notAfter: na,
      basicConstraints: { ca: true },
      keyUsages: KU.keyCertSign | KU.cRLSign,
    },
    issuingKeys,
    { subject: rootYName, keys: rootYKeys },
  );
  certs.push(issuingA, issuingB);

  // --- The diamond leaf ----------------------------------------------------
  const wwwKeys = await genKeys();
  const leafWww = await makeCert(
    {
      id: 'leaf-www', nickname: 'www.example.test (leaf)', role: 'leaf',
      subject: 'CN=www.example.test, O=Example Org', serial: '3001',
      notBefore: nb, notAfter: na,
      san: ['www.example.test'],
      keyUsages: KU.digitalSignature,
      eku: [OID_SERVER_AUTH],
    },
    wwwKeys,
    { subject: issuingName, keys: issuingKeys },
  );
  certs.push(leafWww);

  // --- Trap: basicConstraints CA:FALSE ------------------------------------
  // "Server Ops" is an ordinary end-entity certificate (CA:FALSE, no
  // keyCertSign) whose key is then used to sign a leaf. The signature it
  // produces is cryptographically perfect; the authority is absent.
  const serverOpsKeys = await genKeys();
  const serverOpsName = 'CN=Server Ops, O=Example Org';
  const serverOps = await makeCert(
    {
      id: 'int-serverops', nickname: 'Server Ops (CA:FALSE end-entity)', role: 'intermediate',
      subject: serverOpsName, serial: '4001', notBefore: nb, notAfter: na,
      san: ['ops.example.test'],
      basicConstraints: { ca: false },
      keyUsages: KU.digitalSignature | KU.keyEncipherment,
      eku: [OID_SERVER_AUTH],
    },
    serverOpsKeys,
    { subject: issuingName, keys: issuingKeys },
  );
  const rogueKeys = await genKeys();
  const leafRogue = await makeCert(
    {
      id: 'leaf-rogue', nickname: 'rogue.example.test (leaf)', role: 'leaf',
      subject: 'CN=rogue.example.test, O=Example Org', serial: '4002',
      notBefore: nb, notAfter: na,
      san: ['rogue.example.test'],
      keyUsages: KU.digitalSignature,
      eku: [OID_SERVER_AUTH],
    },
    rogueKeys,
    { subject: serverOpsName, keys: serverOpsKeys },
  );
  certs.push(serverOps, leafRogue);

  // --- Trap: pathLenConstraint exceeded ------------------------------------
  const constrainedKeys = await genKeys();
  const constrainedName = 'CN=Lab Constrained CA, O=Chain of Trust Lab';
  const intConstrained = await makeCert(
    {
      id: 'int-constrained', nickname: 'Constrained CA (pathLen=0)', role: 'intermediate',
      subject: constrainedName, serial: '5001', notBefore: nb, notAfter: na,
      basicConstraints: { ca: true, pathLen: 0 },
      keyUsages: KU.keyCertSign | KU.cRLSign,
    },
    constrainedKeys,
    { subject: rootYName, keys: rootYKeys },
  );
  const deepKeys = await genKeys();
  const deepName = 'CN=Lab Deep CA, O=Chain of Trust Lab';
  const intDeep = await makeCert(
    {
      id: 'int-deep', nickname: 'Deep CA (one level too far)', role: 'intermediate',
      subject: deepName, serial: '5002', notBefore: nb, notAfter: na,
      basicConstraints: { ca: true },
      keyUsages: KU.keyCertSign | KU.cRLSign,
    },
    deepKeys,
    { subject: constrainedName, keys: constrainedKeys },
  );
  const deepLeafKeys = await genKeys();
  const leafDeep = await makeCert(
    {
      id: 'leaf-deep', nickname: 'deep.example.test (leaf)', role: 'leaf',
      subject: 'CN=deep.example.test, O=Example Org', serial: '5003',
      notBefore: nb, notAfter: na,
      san: ['deep.example.test'],
      keyUsages: KU.digitalSignature,
      eku: [OID_SERVER_AUTH],
    },
    deepLeafKeys,
    { subject: deepName, keys: deepKeys },
  );
  certs.push(intConstrained, intDeep, leafDeep);

  // --- Trap: expired intermediate under a valid leaf -----------------------
  const expiredKeys = await genKeys();
  const expiredName = 'CN=Lab Expired CA, O=Chain of Trust Lab';
  const intExpired = await makeCert(
    {
      id: 'int-expired', nickname: 'Expired CA', role: 'intermediate',
      subject: expiredName, serial: '6001',
      notBefore: new Date(now.getTime() - 400 * DAY),
      notAfter: new Date(now.getTime() - 30 * DAY), // expired a month ago
      basicConstraints: { ca: true },
      keyUsages: KU.keyCertSign | KU.cRLSign,
    },
    expiredKeys,
    { subject: rootYName, keys: rootYKeys },
  );
  const archiveKeys = await genKeys();
  const leafArchive = await makeCert(
    {
      id: 'leaf-archive', nickname: 'archive.example.test (leaf)', role: 'leaf',
      subject: 'CN=archive.example.test, O=Example Org', serial: '6002',
      notBefore: nb, notAfter: na, // the leaf itself is perfectly in date
      san: ['archive.example.test'],
      keyUsages: KU.digitalSignature,
      eku: [OID_SERVER_AUTH],
    },
    archiveKeys,
    { subject: expiredName, keys: expiredKeys },
  );
  certs.push(intExpired, leafArchive);

  // --- Trap: hostname vs SAN vs deprecated CN fallback ----------------------
  // CN claims www.example.test; SAN says shop.example.test. SAN governs.
  const shopKeys = await genKeys();
  const leafShop = await makeCert(
    {
      id: 'leaf-shop', nickname: 'CN=www / SAN=shop (leaf)', role: 'leaf',
      subject: 'CN=www.example.test, O=Example Org', serial: '7001',
      notBefore: nb, notAfter: na,
      san: ['shop.example.test'],
      keyUsages: KU.digitalSignature,
      eku: [OID_SERVER_AUTH],
    },
    shopKeys,
    { subject: issuingName, keys: issuingKeys },
  );
  certs.push(leafShop);

  // --- Trap: EKU mismatch (clientAuth cert used for serverAuth) ------------
  const deviceKeys = await genKeys();
  const leafDevice = await makeCert(
    {
      id: 'leaf-device', nickname: 'device.example.test (clientAuth leaf)', role: 'leaf',
      subject: 'CN=device.example.test, O=Example Org', serial: '8001',
      notBefore: nb, notAfter: na,
      san: ['device.example.test'],
      keyUsages: KU.digitalSignature,
      eku: [OID_CLIENT_AUTH], // client authentication ONLY
    },
    deviceKeys,
    { subject: issuingName, keys: issuingKeys },
  );
  certs.push(leafDevice);

  // --- Trap: keyUsage lacking keyCertSign ----------------------------------
  const noSignKeys = await genKeys();
  const noSignName = 'CN=Lab NoCertSign CA, O=Chain of Trust Lab';
  const intNoSign = await makeCert(
    {
      id: 'int-nosign', nickname: 'NoCertSign CA (CA:TRUE, no keyCertSign)', role: 'intermediate',
      subject: noSignName, serial: '9001', notBefore: nb, notAfter: na,
      basicConstraints: { ca: true },
      keyUsages: KU.digitalSignature | KU.cRLSign, // keyCertSign deliberately absent
    },
    noSignKeys,
    { subject: rootYName, keys: rootYKeys },
  );
  const iotKeys = await genKeys();
  const leafIot = await makeCert(
    {
      id: 'leaf-iot', nickname: 'iot.example.test (leaf)', role: 'leaf',
      subject: 'CN=iot.example.test, O=Example Org', serial: '9002',
      notBefore: nb, notAfter: na,
      san: ['iot.example.test'],
      keyUsages: KU.digitalSignature,
      eku: [OID_SERVER_AUTH],
    },
    iotKeys,
    { subject: noSignName, keys: noSignKeys },
  );
  certs.push(intNoSign, leafIot);

  // --- Trap: revoked intermediate (status is a local fixture) --------------
  const retiredKeys = await genKeys();
  const retiredName = 'CN=Lab Retired CA, O=Chain of Trust Lab';
  const intRetired = await makeCert(
    {
      id: 'int-retired', nickname: 'Retired CA (revoked in fixture)', role: 'intermediate',
      subject: retiredName, serial: 'a001', notBefore: nb, notAfter: na,
      basicConstraints: { ca: true },
      keyUsages: KU.keyCertSign | KU.cRLSign,
    },
    retiredKeys,
    { subject: rootYName, keys: rootYKeys },
  );
  const legacyKeys = await genKeys();
  const leafLegacy = await makeCert(
    {
      id: 'leaf-legacy', nickname: 'legacy.example.test (leaf)', role: 'leaf',
      subject: 'CN=legacy.example.test, O=Example Org', serial: 'a002',
      notBefore: nb, notAfter: na,
      san: ['legacy.example.test'],
      keyUsages: KU.digitalSignature,
      eku: [OID_SERVER_AUTH],
    },
    legacyKeys,
    { subject: retiredName, keys: retiredKeys },
  );
  certs.push(intRetired, leafLegacy);

  // --- Trap: self-signed leaf presented as its own root ---------------------
  const standaloneKeys = await genKeys();
  const standaloneName = 'CN=standalone.example.test, O=Example Org';
  const leafStandalone = await makeCert(
    {
      id: 'leaf-standalone', nickname: 'standalone.example.test (self-signed)', role: 'leaf',
      subject: standaloneName, serial: 'b001', notBefore: nb, notAfter: na,
      san: ['standalone.example.test'],
      keyUsages: KU.digitalSignature,
      eku: [OID_SERVER_AUTH],
    },
    standaloneKeys,
    { subject: standaloneName, keys: standaloneKeys }, // signs itself
  );
  certs.push(leafStandalone);

  const map = new Map(certs.map((c) => [c.id, c]));
  return {
    all: certs,
    byId(id: string): LabCert {
      const c = map.get(id);
      if (!c) throw new Error(`unknown lab cert id: ${id}`);
      return c;
    },
  };
}
