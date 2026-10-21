const $ = (id) => document.getElementById(id);
const MAX = 0xffffffffn;
const media = matchMedia('(prefers-reduced-motion: reduce)');
let report, current, phase = 0, timer = null, inView = true;
const isInt = (value, max = Number(MAX)) => Number.isSafeInteger(value) && value >= 0 && value <= max;
const sameKeys = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join('|') === [...keys].sort().join('|');
const rangeExpected = ({total, offset, count}) => Number(BigInt(offset) <= BigInt(total) && BigInt(count) <= BigInt(total) - BigInt(offset));
const format = (value) => value.toLocaleString('en-US');
const set = (id, value) => { $(id).textContent = value; };

function stop() {
  clearInterval(timer);
  timer = null;
  set('play', media.matches ? 'Motion off' : 'Run trace');
}
function setPhase(value) {
  phase = value;
  document.querySelector('.glass').dataset.phase = String(phase);
  set('trace-phase', ['01 / operands', '02 / addition', '03 / retained word'][phase]);
}
function row(term, value) {
  const div = document.createElement('div');
  const dt = document.createElement('dt');
  const dd = document.createElement('dd');
  dt.textContent = term;
  dd.textContent = value;
  div.append(dt, dd);
  return div;
}
function nativeRow(name, values, expected) {
  const tr = document.createElement('tr');
  for (const value of [name, values.O0, values.O2]) {
    const td = document.createElement('td');
    td.textContent = String(value);
    if (typeof value === 'number' && value !== expected) td.className = 'bad';
    tr.append(td);
  }
  return tr;
}
function show(item, imported = false) {
  stop();
  setPhase(0);
  current = item;
  const boolean = 'value' in item.input;
  const expected = boolean ? (item.input.value < 2 ? item.input.value : -1) : rangeExpected(item.input);
  const sum = boolean ? BigInt(item.input.value) : BigInt(item.input.offset) + BigInt(item.input.count);
  const low = sum & MAX;
  const carry = sum > MAX ? 1 : 0;
  $('inputs').replaceChildren(...Object.entries(item.input).map(([key, value]) => row(key, format(value))));
  set('sum', `0x${sum.toString(16).toUpperCase().padStart(9, '0')}`);
  set('low', `0x${low.toString(16).toUpperCase().padStart(8, '0')}`);
  $('carry-cell').firstChild.textContent = String(carry);
  document.querySelector('.glass').dataset.carry = String(carry);
  set('sum-state', boolean ? 'BYTE DECODER' : carry ? 'CARRY = 1' : 'CARRY = 0');
  $('word').replaceChildren(...low.toString(2).padStart(32, '0').split('').map((bit) => {
    const span = document.createElement('span');
    span.textContent = bit;
    span.className = bit === '1' ? 'bit on' : 'bit';
    return span;
  }));
  const functions = imported ? [item.function] : ['legacy_range', 'bounded_range'];
  $('native').replaceChildren(...functions.map((name) => nativeRow(name,
    imported ? item.recorded : {O0:item.native.O0[name], O2:item.native.O2[name]}, expected)));
  set('oracle', String(expected));
  set('mechanism', boolean ? `The byte is ${item.input.value}. Canonical Boolean decoding accepts only 0 or 1; other bytes return −1.` :
    carry ? `The full sum is ${format(Number(sum))}. The carry bit leaves the uint32 result. The comparison receives ${format(Number(low))}.` :
      `The full sum is ${format(Number(sum))}. No carry is lost; the comparison receives the same value.`);
  set('verdict-explain', boolean ? '−1 means an invalid encoded Boolean.' : expected ? 'The interval fits the mathematical bound.' : 'The interval exceeds the mathematical bound. A native return of 1 is a false accept.');
  set('record-origin', imported ? 'Imported recorded claims. Run the Python replay command to verify them natively.' : 'From the checked-in native run. 1 = accept; 0 = reject.');
  $('play').disabled = media.matches || boolean;
  $('step').disabled = boolean;
}

export function parseReplay(text, sourceHash) {
  if (new TextEncoder().encode(text).length > 16384) throw new Error('Replay exceeds 16 KiB.');
  // JSON.parse supplies values only; nothing in the uploaded file is evaluated as code.
  const item = JSON.parse(text);
  if (!sameKeys(item, ['schema','function','input','expected','recorded','fixture_sha256']) || item.schema !== 'carryglass.replay.v1') throw new Error('Unsupported replay schema.');
  if (!['legacy_boolean','canonical_boolean','legacy_range','bounded_range'].includes(item.function)) throw new Error('Unknown fixture function.');
  if (item.fixture_sha256 !== sourceHash) throw new Error('Replay belongs to a different fixture source.');
  const boolean = item.function.endsWith('boolean');
  const keys = boolean ? ['value'] : ['total','offset','count'];
  if (!sameKeys(item.input, keys) || !Object.values(item.input).every((v) => isInt(v, boolean ? 255 : Number(MAX)))) throw new Error('Input is outside the declared integer domain.');
  const expected = boolean ? (item.input.value < 2 ? item.input.value : -1) : rangeExpected(item.input);
  if (typeof item.expected !== 'number' || item.expected !== expected) throw new Error('Expected result differs from the integer oracle.');
  const returns = item.function === 'canonical_boolean' ? [-1,0,1] : [0,1];
  if (!sameKeys(item.recorded, ['O0','O2']) || !Object.values(item.recorded).every((v) => typeof v === 'number' && returns.includes(v))) throw new Error('Invalid native return value.');
  return item;
}

$('case').addEventListener('change', () => {
  set('import-status', '16 KiB maximum. Values remain in this tab.');
  show(report.examples[Number($('case').value)]);
});
$('step').addEventListener('click', () => { stop(); setPhase((phase + 1) % 3); });
$('play').addEventListener('click', () => {
  if (timer) { stop(); return; }
  if (media.matches || document.hidden || !inView) return;
  set('play', 'Pause trace');
  timer = setInterval(() => setPhase((phase + 1) % 3), 1100);
});
$('replay-file').addEventListener('change', async (event) => {
  const file = event.target.files[0];
  if (!file || !report) return;
  try {
    if (file.size > 16384) throw new Error('Replay exceeds 16 KiB.');
    const replay = parseReplay(await file.text(), report.source_sha256['fixture.c']);
    show(replay, true);
    $('case').selectedIndex = -1;
    set('import-status', 'Replay values loaded. Native claims are not executed in this tab.');
  } catch (error) {
    set('import-status', `Not loaded: ${error.message}`);
  }
  event.target.value = '';
});
document.addEventListener('visibilitychange', () => { if (document.hidden) stop(); });
addEventListener('pagehide', stop);
media.addEventListener('change', () => { stop(); $('play').disabled = media.matches || Boolean(current && 'value' in current.input); });
new IntersectionObserver(([entry]) => { inView = entry.isIntersecting; if (!inView) stop(); }).observe($('instrument'));

try {
  const response = await fetch('evidence/report.json', {cache:'no-cache'});
  if (!response.ok) throw new Error(`Record HTTP ${response.status}`);
  report = await response.json();
  if (report.schema !== 'carryglass.report.v1' || report.passed !== true || !Array.isArray(report.examples) || report.examples.length !== 6 || report.builds.length !== 2) throw new Error('Unexpected native record.');
  $('case').replaceChildren(...report.examples.map((item, index) => {
    const option = document.createElement('option');
    option.value = String(index);
    option.textContent = `${String(index + 1).padStart(2,'0')} / ${item.label}`;
    return option;
  }));
  $('case').disabled = false;
  const run = report.builds[0];
  set('record-status', `${report.recorded_at.slice(0,10)} / O0 + O2 / recorded`);
  set('sample-summary', `${format(run.range_inputs)} range triples per build. ${format(run.legacy_false_accepts)} legacy false accepts. Zero corrected-range disagreements in this run.`);
  $('receipt').replaceChildren(...[
    ['Byte domain', `${run.boolean_inputs} / 256 values`],
    ['Seeded streams', report.seeds.join(' · ')],
    ['Metamorphic calls / build', format(run.metamorphic_native_calls)],
    ['O0 ↔ O2 disagreements', `${report.optimization_disagreements} / ${format(report.optimization_comparisons)}`],
    ['Reducer predicate calls', String(run.reduction.calls)],
    ['Reducer conclusion', 'candidate-local fixed point']
  ].map(([term, value]) => row(term, value)));
  set('identity', `${report.compiler}\n\nfixture.c\n${report.source_sha256['fixture.c']}\n\n${report.builds.map((b) => `${b.optimization} DLL\n${b.sha256}`).join('\n\n')}\n\n${report.reducer.guarantee}`);
  show(report.examples[0]);
} catch (error) {
  set('record-status', 'Native record unavailable');
  set('mechanism', `Open this page through the documented local HTTP server. ${error.message}`);
  set('sample-summary', 'No native result has been loaded.');
}
