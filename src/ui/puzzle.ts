import { STAGES, type Stage } from '../pki/scenarios';
import { validatePath } from '../pki/validate';
import type { CheckId, LabPki } from '../pki/types';
import { CHECK_NAMES, checkTable, chipRow, el } from './common';

/**
 * Puzzle mode: the learner IS the validator. They assemble a path from the
 * bag and rule ACCEPT or REJECT (naming the failing check). Grading runs the
 * real RFC 5280 §6 implementation on the exact path the learner built.
 */
export function renderPuzzle(root: HTMLElement, pki: LabPki): void {
  const solved = new Set<string>();
  let current = 0;
  let path: string[] = [];
  let linkFacts: string[] = []; // human-readable real-ECDSA results per added link

  root.append(
    el('p', { class: 'lede' }, [
      'Each stage hands you a leaf certificate, a bag of candidates, and a trust store. Build the ' +
        'chain (leaf upward), then rule. Signature facts are shown as you build — cryptography ' +
        'answers instantly. Everything else on the checklist is your call. The stage is graded by ' +
        'the real validator, and it will tell you exactly which check you missed.',
    ]),
  );

  const stageNav = el('ol', { class: 'stage-list', 'aria-label': 'Puzzle stages' });
  const scoreLine = el('p', { class: 'score-line', role: 'status', 'aria-live': 'polite' });
  const stageBox = el('div');
  root.append(stageNav, scoreLine, stageBox);

  function renderNav(): void {
    stageNav.replaceChildren(
      ...STAGES.map((s, i) =>
        el('li', {}, [
          el(
            'button',
            {
              type: 'button',
              class: solved.has(s.id) ? 'stage-solved' : '',
              'aria-pressed': i === current ? 'true' : 'false',
              onclick: () => {
                current = i;
                resetStage();
              },
            },
            [`${s.n}. ${s.title}${solved.has(s.id) ? ' ✓' : ''}`],
          ),
        ]),
      ),
    );
    scoreLine.textContent = `Solved ${solved.size} of ${STAGES.length} stages.`;
  }

  function resetStage(): void {
    const stage = STAGES[current];
    path = [stage.leafId];
    linkFacts = [];
    renderNav();
    renderStage();
  }

  function stageOpts(stage: Stage) {
    return {
      trustStore: stage.trustIds.map((id) => pki.byId(id)),
      host: stage.host,
      requiredEku: stage.requiredEku,
      revoked: new Set(stage.revokedIds),
    };
  }

  function renderStage(): void {
    const stage = STAGES[current];
    stageBox.replaceChildren();

    stageBox.append(
      el('h3', {}, [`Stage ${stage.n}: ${stage.title}`]),
      el('p', {}, [stage.brief]),
      el('ul', { class: 'context-list' }, [
        el('li', {}, [el('strong', {}, ['Connecting to host: ']), stage.host ?? '(none — no hostname check)']),
        el('li', {}, [el('strong', {}, ['Validating for: ']), stage.requiredEku ?? '(no EKU requirement)']),
        el('li', {}, [
          el('strong', {}, ['Trust store: ']),
          stage.trustIds.map((id) => pki.byId(id).nickname).join(', '),
        ]),
        el('li', {}, [
          el('strong', {}, ['Revocation fixture (local, no network fetch): ']),
          stage.revokedIds.length === 0
            ? 'nothing revoked'
            : `${stage.revokedIds.map((id) => pki.byId(id).nickname).join(', ')} — REVOKED`,
        ]),
      ]),
    );

    const cols = el('div', { class: 'puzzle-cols' });
    const bagCol = el('div');
    const pathCol = el('div');
    cols.append(pathCol, bagCol);
    stageBox.append(cols);

    // --- your path ---------------------------------------------------------
    const pathList = el('ul', { class: 'cert-list', 'aria-label': 'Your path, leaf first' });
    const pathHeader = el('h3', {}, ['Your path (leaf first)']);
    const undoBtn = el(
      'button',
      {
        type: 'button',
        onclick: () => {
          if (path.length > 1) {
            path.pop();
            linkFacts.pop();
            renderStage();
          }
        },
      },
      ['Remove last certificate'],
    );
    if (path.length <= 1) undoBtn.setAttribute('disabled', '');
    pathCol.append(pathHeader, pathList, el('div', { class: 'controls' }, [undoBtn]));

    for (let i = 0; i < path.length; i++) {
      const cert = pki.byId(path[i]);
      const item = el('li', {}, [
        el('span', { class: 'cert-name', text: `${i === 0 ? 'Leaf: ' : ''}${cert.nickname}` }),
      ]);
      if (i > 0) item.append(el('span', { class: 'link-fact', text: linkFacts[i - 1] ?? '' }));
      pathList.append(item);
    }

    // --- the bag ------------------------------------------------------------
    const bagIds = [...stage.bagIds, ...stage.trustIds];
    bagCol.append(
      el('h3', {}, ['The bag (intermediates on offer + trust-store roots)']),
      bagIds.length === 0 ? el('p', { class: 'lede' }, ['The server sent nothing but the leaf.']) : '',
    );
    const bagList = el('ul', { class: 'cert-list', 'aria-label': 'Certificates on offer' });
    bagCol.append(bagList);
    for (const id of bagIds) {
      const cert = pki.byId(id);
      const inPath = path.includes(id);
      const addBtn = el(
        'button',
        {
          type: 'button',
          onclick: () => void addToPath(id),
        },
        ['Add to path'],
      );
      if (inPath) addBtn.setAttribute('disabled', '');
      bagList.append(
        el('li', {}, [
          el('span', {
            class: 'cert-name',
            text: `${cert.nickname}${stage.trustIds.includes(id) ? ' (trust store)' : ''}`,
          }),
          addBtn,
        ]),
      );
    }

    // --- verdict controls ----------------------------------------------------
    const culpritSelect = el('select', { 'aria-label': 'Which check fails?' });
    culpritSelect.append(el('option', { value: '', text: '…because this check fails:' }));
    for (const [id, name] of Object.entries(CHECK_NAMES)) {
      culpritSelect.append(el('option', { value: id, text: name }));
    }
    const acceptBtn = el('button', { type: 'button', class: 'primary' }, ['ACCEPT this chain']);
    const rejectBtn = el('button', { type: 'button' }, ['REJECT']);
    const gradeBox = el('div', { role: 'status', 'aria-live': 'polite' });
    stageBox.append(
      el('h3', {}, ['Your ruling']),
      el('div', { class: 'controls' }, [acceptBtn, rejectBtn, culpritSelect]),
      gradeBox,
    );

    acceptBtn.addEventListener('click', () => void grade('ACCEPT', null));
    rejectBtn.addEventListener('click', () => {
      const culprit = (culpritSelect.value || null) as CheckId | null;
      void grade('REJECT', culprit);
    });

    async function addToPath(id: string): Promise<void> {
      const top = pki.byId(path[path.length - 1]);
      const cand = pki.byId(id);
      // Real ECDSA, immediately — the crypto fact is free; the judgment isn't.
      const namesChain = top.cert.issuer === cand.cert.subject;
      const sigOk =
        namesChain &&
        (await top.cert.verify({ publicKey: cand.cert.publicKey, signatureOnly: true }));
      path.push(id);
      linkFacts.push(
        !namesChain
          ? `Fact: "${cand.nickname}" is not the named issuer of the certificate below it (DN mismatch).`
          : sigOk
            ? `Fact: signature of the certificate below verifies under "${cand.nickname}" (real ECDSA ✓).`
            : `Fact: signature does NOT verify under "${cand.nickname}" (real ECDSA ✗).`,
      );
      renderStage();
    }

    async function grade(learnerVerdict: 'ACCEPT' | 'REJECT', culprit: CheckId | null): Promise<void> {
      const labPath = path.map((id) => pki.byId(id));
      const result = await validatePath(labPath, stageOpts(stage));
      const failedIds = [...new Set(result.failures.map((f) => f.id))];
      const verdictRight = learnerVerdict === result.verdict;
      const culpritRight =
        result.verdict === 'ACCEPT' || (culprit !== null && failedIds.includes(culprit));
      const pathIsIntended =
        path.length === stage.intendedPathIds.length &&
        path.every((id, i) => id === stage.intendedPathIds[i]);

      gradeBox.replaceChildren();

      // Verdict separation, always: fact chip + verdict chip.
      gradeBox.append(chipRow(result));

      if (learnerVerdict === 'ACCEPT' && result.verdict === 'REJECT') {
        // The alarm state: forged-but-accepted. Color tracks system integrity.
        gradeBox.append(
          el('div', { class: 'alarm' }, [
            el('p', { class: 'alarm-title' }, ['⚠ You accepted a chain the RFC 5280 validator rejects.']),
            el('p', {}, [
              `This is how real vulnerabilities look from the inside: ${
                result.signatureChainOk
                  ? 'every signature in your chain is genuinely valid — and the chain still must be refused. '
                  : 'a signature in your chain does not even verify. '
              }The check you missed: ${result.failures
                .map((f) => f.label)
                .join('; ')}.`,
            ]),
          ]),
        );
      } else if (learnerVerdict === 'REJECT' && result.verdict === 'ACCEPT') {
        gradeBox.append(
          el('div', { class: 'callout-plain' }, [
            el('p', {}, [
              el('strong', {}, ['Too strict: ']),
              'the validator accepts this path — every check passes. Rejecting valid chains has real ' +
                'costs too (outages), but it fails safe. Look at the table to see each check pass.',
            ]),
          ]),
        );
      } else if (verdictRight && result.verdict === 'REJECT' && !culpritRight) {
        gradeBox.append(
          el('div', { class: 'callout-plain' }, [
            el('p', {}, [
              el('strong', {}, ['Right verdict, wrong reason: ']),
              culprit
                ? `you blamed "${CHECK_NAMES[culprit]}", but what actually fails is: ${result.failures
                    .map((f) => f.label)
                    .join('; ')}.`
                : `pick the failing check from the list — knowing WHY a chain fails is the skill this lab drills.`,
            ]),
          ]),
        );
      } else {
        gradeBox.append(
          el('div', { class: 'callout-ok' }, [
            el('p', {}, [
              el('strong', {}, ['✓ Correct. ']),
              result.verdict === 'REJECT'
                ? `This chain must be refused — and note the signature fact beside the verdict: ${
                    result.signatureChainOk ? 'the cryptography is flawless.' : 'here even the crypto fails.'
                  }`
                : 'Valid chain, correctly accepted.',
            ]),
          ]),
        );
      }

      if (!pathIsIntended) {
        gradeBox.append(
          el('p', { class: 'lede' }, [
            'You were graded on the path exactly as you built it. To complete the stage, assemble the ' +
              'full intended path to the anchor — the interesting question is why THAT one passes or fails.',
          ]),
        );
      }

      gradeBox.append(checkTable(result, `Validator checklist for stage ${stage.n}`));

      const stageSolved = verdictRight && culpritRight && pathIsIntended;
      if (stageSolved) {
        solved.add(stage.id);
        gradeBox.append(
          el('div', { class: 'callout-plain' }, [
            el('p', {}, [el('strong', {}, ['Lesson: ']), stage.lesson]),
          ]),
        );
      }
      renderNav();
    }
  }

  const resetAll = el(
    'button',
    {
      type: 'button',
      onclick: () => {
        solved.clear();
        current = 0;
        resetStage();
      },
    },
    ['Reset all stages'],
  );
  root.append(el('div', { class: 'controls' }, [resetAll]));

  resetStage();
}
