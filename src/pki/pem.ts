import * as x509 from '@peculiar/x509';
import type { LabCert } from './types';

const PEM_BLOCK = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
const MAX_INPUT_BYTES = 256 * 1024;
const MAX_CERTS = 16;

/**
 * Parse pasted PEM text into LabCert records for the bring-your-own-chain
 * mode. Everything stays in this browser tab: nothing is uploaded, fetched,
 * or persisted. Fail-closed: malformed input throws with a plain message
 * rather than yielding a partial chain.
 */
export function parsePemCertificates(text: string, idPrefix: string): LabCert[] {
  if (text.length > MAX_INPUT_BYTES) {
    throw new Error(`input too large (max ${MAX_INPUT_BYTES / 1024} KiB)`);
  }
  const blocks = text.match(PEM_BLOCK) ?? [];
  if (blocks.length === 0) {
    throw new Error('no "-----BEGIN CERTIFICATE-----" blocks found in the input');
  }
  if (blocks.length > MAX_CERTS) {
    throw new Error(`too many certificates (max ${MAX_CERTS})`);
  }
  return blocks.map((pem, i) => {
    let cert: x509.X509Certificate;
    try {
      cert = new x509.X509Certificate(pem);
    } catch (err) {
      throw new Error(
        `certificate ${i + 1} did not parse as X.509 DER: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    const cn = cert.subjectName.getField('CN')[0];
    const bc = cert.getExtension(x509.BasicConstraintsExtension);
    const selfIssued = cert.subject === cert.issuer;
    const role: LabCert['role'] = bc?.ca ? (selfIssued ? 'root' : 'intermediate') : 'leaf';
    return {
      id: `${idPrefix}-${i}`,
      nickname: cn ?? cert.subject,
      role,
      cert,
    };
  });
}
