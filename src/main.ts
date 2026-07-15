import './style.css';
import { generateLabPki } from './pki/certgen';
import { renderInspector } from './ui/inspector';
import { renderMechanism } from './ui/mechanism';
import { renderPuzzle } from './ui/puzzle';
import { renderTrust } from './ui/trust';

// [extension] point: a future "import your own PEM chain" mode would plug in
// here — parse user PEM into LabCert records and feed the same validator.

async function boot(): Promise<void> {
  const loading = document.getElementById('loading')!;
  try {
    const pki = await generateLabPki();
    loading.textContent = 'Lab PKI ready — 19 certificates, fresh ECDSA P-256 keys for this session only.';

    for (const [id, render] of [
      ['mechanism', renderMechanism],
      ['puzzle', renderPuzzle],
      ['truststore', renderTrust],
      ['inspector', renderInspector],
    ] as const) {
      const section = document.getElementById(id)!;
      section.hidden = false;
      render(section, pki);
    }
  } catch (err) {
    loading.textContent = `Failed to generate the lab PKI: ${err instanceof Error ? err.message : String(err)}`;
  }
}

void boot();
