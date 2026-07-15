import './style.css';
import { generateLabPki } from './pki/certgen';
import { renderByo } from './ui/byo';
import { renderInspector } from './ui/inspector';
import { renderMechanism } from './ui/mechanism';
import { renderPuzzle } from './ui/puzzle';
import { renderTrust } from './ui/trust';

async function boot(): Promise<void> {
  const loading = document.getElementById('loading')!;
  try {
    const pki = await generateLabPki();
    loading.textContent = 'Lab PKI ready — 19 certificates, fresh ECDSA P-256 keys for this session only.';

    const section = (id: string): HTMLElement => {
      const s = document.getElementById(id)!;
      s.hidden = false;
      return s;
    };

    renderMechanism(section('mechanism'), pki);
    // Inspector renders before the puzzle so failed checks can deep-link to
    // their evidence; DOM order is fixed by the static section shells.
    const inspector = renderInspector(section('inspector'), pki);
    renderPuzzle(section('puzzle'), pki, inspector.show);
    renderTrust(section('truststore'), pki);
    renderByo(section('byo'), pki);
  } catch (err) {
    loading.textContent = `Failed to generate the lab PKI: ${err instanceof Error ? err.message : String(err)}`;
  }
}

void boot();
