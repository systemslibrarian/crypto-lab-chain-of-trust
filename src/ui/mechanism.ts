import { buildAndValidate } from '../pki/build';
import type { BuildOutcome, BuildStep, LabPki } from '../pki/types';
import { el } from './common';

/**
 * The headline mechanism, shown not told: the same leaf has two
 * cryptographically valid parents (a cross-signed issuing CA), one branch
 * dies on nameConstraints, and a builder that does not backtrack reports
 * failure for a leaf that has a perfectly valid path.
 */
export function renderMechanism(root: HTMLElement, pki: LabPki): void {
  root.append(
    el('p', { class: 'lede' }, [
      'The Issuing CA below was cross-signed: one key, two certificates. Through cross-sign A it chains ' +
        'to Root X — but Root X constrained that branch to *.internal.test names (nameConstraints). ' +
        'Through cross-sign B it chains cleanly to Root Y. Both branches carry flawless ECDSA signatures. ' +
        'Watch what each builder does with that.',
    ]),
  );

  // --- diagram -------------------------------------------------------------
  const nodes: Record<string, HTMLElement> = {};
  const mkNode = (id: string, name: string, sub: string) => {
    const n = el('div', { class: 'node', 'data-node': id }, [
      el('div', { class: 'node-name', text: name }),
      el('div', { class: 'node-sub', text: sub }),
    ]);
    nodes[id] = n;
    return n;
  };

  const grid = el('div', { class: 'diamond-grid' }, [
    el('div'),
    mkNode('issuing-a', 'Issuing CA — cross-sign A', 'signed by Root X · nameConstraints: permit only internal.test'),
    mkNode('root-x', 'Root X', 'in the trust store'),
    mkNode('leaf-www', 'www.example.test', 'the leaf being validated'),
    el('div', { class: 'node-spacer' }),
    el('div', { class: 'node-spacer' }),
    el('div'),
    mkNode('issuing-b', 'Issuing CA — cross-sign B', 'signed by Root Y · same public key as A, no constraints'),
    mkNode('root-y', 'Root Y', 'in the trust store'),
  ]);
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('class', 'diamond-svg');
  svg.setAttribute('aria-hidden', 'true');
  const wrap = el('div', { class: 'diamond-wrap' });
  wrap.append(svg, grid);
  // On narrow screens the diagram keeps its diamond shape and scrolls
  // horizontally instead of collapsing (the shape IS the lesson).
  const scroller = el(
    'div',
    { class: 'diamond-scroll', tabindex: '0', role: 'region', 'aria-label': 'Certificate hierarchy diagram' },
    [wrap],
  );
  root.append(scroller);

  const EDGES: [string, string, string][] = [
    ['leaf-www', 'issuing-a', 'edge-la'],
    ['leaf-www', 'issuing-b', 'edge-lb'],
    ['issuing-a', 'root-x', 'edge-ax'],
    ['issuing-b', 'root-y', 'edge-by'],
  ];
  const edgeEls = new Map<string, SVGLineElement>();
  function drawEdges(): void {
    svg.replaceChildren();
    edgeEls.clear();
    const wrapBox = wrap.getBoundingClientRect();
    if (wrapBox.width === 0) return;
    svg.setAttribute('viewBox', `0 0 ${wrapBox.width} ${wrapBox.height}`);
    for (const [fromId, toId, key] of EDGES) {
      const a = nodes[fromId].getBoundingClientRect();
      const b = nodes[toId].getBoundingClientRect();
      const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line.setAttribute('x1', String(a.right - wrapBox.left));
      line.setAttribute('y1', String(a.top + a.height / 2 - wrapBox.top));
      line.setAttribute('x2', String(b.left - wrapBox.left));
      line.setAttribute('y2', String(b.top + b.height / 2 - wrapBox.top));
      line.setAttribute('class', 'edge');
      line.dataset.state = '';
      svg.append(line);
      edgeEls.set(key, line);
    }
  }
  new ResizeObserver(() => {
    drawEdges();
    for (const [key, state] of edgeStates) setEdge(key, state);
  }).observe(wrap);

  type EdgeState = '' | 'active' | 'rejected' | 'accepted';
  const edgeStates = new Map<string, EdgeState>();
  function setEdge(key: string, state: EdgeState): void {
    edgeStates.set(key, state);
    const line = edgeEls.get(key);
    if (line) line.setAttribute('class', `edge ${state ? `edge-${state}` : ''}`);
  }
  function setNode(id: string, state: '' | 'active' | 'rejected' | 'accepted'): void {
    const n = nodes[id];
    if (!n) return;
    n.className = `node ${state ? `node-${state}` : ''}`;
  }
  function resetStates(): void {
    for (const id of Object.keys(nodes)) setNode(id, '');
    for (const [, , key] of EDGES) setEdge(key, '');
  }

  const EDGE_FOR_PAIR: Record<string, string> = {
    'leaf-www>issuing-a': 'edge-la',
    'leaf-www>issuing-b': 'edge-lb',
    'issuing-a>root-x': 'edge-ax',
    'issuing-b>root-y': 'edge-by',
  };

  // --- controls + log ------------------------------------------------------
  const naiveBtn = el('button', { type: 'button' }, [
    '▶ Run the NAIVE builder (no backtracking — deliberately broken)',
  ]);
  const smartBtn = el('button', { type: 'button', class: 'primary' }, [
    '▶ Run the BACKTRACKING builder (RFC 4158 style — the fix)',
  ]);
  root.append(
    el('div', { class: 'controls' }, [naiveBtn, smartBtn]),
    el('p', { class: 'lede' }, [
      'The naive mode is not the default behavior of this lab — it is the historical bug, on display. ' +
        'Cross-sign A is first in the bag, exactly the order that bit real clients.',
    ]),
  );

  const log = el('ol', { class: 'step-log-list' });
  const logWrap = el(
    'div',
    { class: 'step-log', role: 'log', 'aria-label': 'Path builder step log', tabindex: '0' },
    [log],
  );
  const outcomeBox = el('div', { role: 'status', 'aria-live': 'polite' });
  root.append(logWrap, outcomeBox);

  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  let running = false;

  async function run(backtrack: boolean): Promise<void> {
    if (running) return;
    running = true;
    naiveBtn.setAttribute('disabled', '');
    smartBtn.setAttribute('disabled', '');
    log.replaceChildren();
    outcomeBox.replaceChildren();
    resetStates();
    drawEdges();

    // The real thing: real bag order, real trust store, real validator.
    const outcome = await buildAndValidate({
      leaf: pki.byId('leaf-www'),
      bag: [pki.byId('issuing-a'), pki.byId('issuing-b')],
      validateOpts: {
        trustStore: [pki.byId('root-x'), pki.byId('root-y')],
        host: 'www.example.test',
        requiredEku: 'serverAuth',
      },
      backtrack,
    });

    for (const step of outcome.steps) {
      appendStep(step);
      applyStepToDiagram(step);
      if (!reduceMotion) await pause(650);
    }
    renderOutcome(outcome);
    naiveBtn.removeAttribute('disabled');
    smartBtn.removeAttribute('disabled');
    running = false;
  }

  function appendStep(step: BuildStep): void {
    const tagClass =
      step.action === 'path-accepted'
        ? 'step-tag-ok'
        : step.action === 'path-indeterminate'
          ? 'step-tag-warn'
        : step.action === 'path-rejected' || step.action === 'give-up' || step.action === 'link-bad'
          ? 'step-tag-bad'
          : step.action === 'backtrack' || step.action === 'dead-end'
            ? 'step-tag-warn'
            : 'step-tag-neutral';
    log.append(
      el('li', {}, [
        el('span', { class: `step-tag ${tagClass}`, text: step.action.toUpperCase() }),
        step.note,
      ]),
    );
    logWrap.scrollTop = logWrap.scrollHeight;
  }

  function applyStepToDiagram(step: BuildStep): void {
    const ids = step.pathIds;
    const pairKey = ids.length >= 2 ? `${ids[ids.length - 2]}>${ids[ids.length - 1]}` : null;
    switch (step.action) {
      case 'consider':
        if (step.certId) setNode(step.certId, 'active');
        break;
      case 'link-ok':
        if (pairKey && EDGE_FOR_PAIR[pairKey]) setEdge(EDGE_FOR_PAIR[pairKey], 'active');
        break;
      case 'path-rejected':
        for (let i = 0; i + 1 < ids.length; i++) {
          const k = EDGE_FOR_PAIR[`${ids[i]}>${ids[i + 1]}`];
          if (k) setEdge(k, 'rejected');
        }
        for (const id of ids) setNode(id, 'rejected');
        break;
      case 'path-accepted':
        for (let i = 0; i + 1 < ids.length; i++) {
          const k = EDGE_FOR_PAIR[`${ids[i]}>${ids[i + 1]}`];
          if (k) setEdge(k, 'accepted');
        }
        for (const id of ids) setNode(id, 'accepted');
        break;
      case 'path-indeterminate':
        break;
      case 'backtrack':
        if (step.certId) setNode(step.certId, '');
        break;
      default:
        break;
    }
  }

  function renderOutcome(outcome: BuildOutcome): void {
    outcomeBox.replaceChildren();
    if (!outcome.found) {
      outcomeBox.append(
        el('div', { class: 'alarm' }, [
          el('p', { class: 'alarm-title' }, ['⚠ The naive builder reports: no valid chain — connection fails.']),
          el('p', {}, [
            'That answer is wrong in the way that matters: a fully valid path (cross-sign B → Root Y) ' +
              'sat in the bag the whole time. The builder found ONE cryptographically valid chain, ' +
              'validation failed it on a policy check (nameConstraints — the signatures were perfect), ' +
              'and it never went back to try the alternative.',
          ]),
          el('p', {}, [
            'This exact bug class shipped: when DST Root X3 expired in September 2021, OpenSSL 1.0.2 ' +
              'clients rejected millions of valid Let’s Encrypt chains because the builder committed ' +
              'to the expired cross-sign path and reported that path’s error (there, expiry; here, ' +
              'nameConstraints) instead of backtracking to the valid one.',
          ]),
        ]),
      );
    } else {
      outcomeBox.append(
        el('div', { class: 'callout-ok' }, [
          el('p', {}, [
            el('strong', {}, ['✓ Backtracking found the valid path: ']),
            'leaf → cross-sign B → Root Y, after rejecting the A-branch for nameConstraints. Same leaf, ' +
              `same bag, same trust store as the naive run — the only difference is that the search kept going. ` +
              `Candidate paths validated: ${outcome.pathsTried}.`,
          ]),
          el('p', {}, [
            'Note what did NOT change between the two runs: not one byte, not one signature. ' +
              '"Path building" and "path validation" are different problems — and only one of them ' +
              'is about cryptography.',
          ]),
        ]),
      );
    }
  }

  naiveBtn.addEventListener('click', () => void run(false));
  smartBtn.addEventListener('click', () => void run(true));
  drawEdges();
}

function pause(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
