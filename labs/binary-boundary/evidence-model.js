// Original mapping layer for the recorded fixture exports. No disassembly or execution.
export const BUILDS = Object.freeze(['O0', 'O2']);
export const FUNCTIONS = Object.freeze(['legacy_boolean', 'canonical_boolean', 'legacy_range', 'bounded_range']);
const required = (condition, message) => { if (!condition) throw new Error(message); };
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const count = (value, min = 0, max = 1000000) => Number.isSafeInteger(value) && value >= min && value <= max;
const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const text = (value, max) => typeof value === 'string' && value.trim().length > 0 && value.length <= max;
const address = value => typeof value === 'string' && /^[0-9a-f]{1,16}$/.test(value);
const freeze = value => {
  if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); }
  return value;
};

function twoBuilds(rows, label) {
  required(Array.isArray(rows) && rows.length === 2, `${label}: expected exactly O0 and O2`);
  const result = {};
  for (const row of rows) {
    required(object(row) && BUILDS.includes(row.optimization) && !result[row.optimization], `${label}: missing or duplicate build`);
    required(hash(row.sha256), `${label}: invalid binary identity`);
    result[row.optimization] = row;
  }
  return result;
}

function functionRecord(input, optimization) {
  const label = `${optimization}/${input?.name || 'unknown'}`;
  required(object(input) && FUNCTIONS.includes(input.name), `${label}: unexpected function`);
  required(address(input.entry), `${label}: missing or invalid entry`);
  required(text(input.decompiled_c, 65536), `${label}: recovered C is missing`);
  required(count(input.instruction_count, 1, 4096), `${label}: invalid instruction count`);
  required(Array.isArray(input.blocks) && input.blocks.length > 0 && input.blocks.length <= 128, `${label}: missing or oversized block list`);
  const starts = new Set(), instructionAddresses = new Set();
  const blocks = input.blocks.map(block => {
    required(object(block) && address(block.start) && !starts.has(block.start), `${label}: missing or duplicate block address`);
    starts.add(block.start);
    required(Array.isArray(block.instructions) && block.instructions.length > 0 && block.instructions.length <= 4096, `${label}: missing block instructions`);
    let previousEnd = null;
    const instructions = block.instructions.map(instruction => {
      required(object(instruction) && address(instruction.address) && !instructionAddresses.has(instruction.address), `${label}: missing or duplicate instruction address`);
      required(text(instruction.text, 512), `${label}: instruction text is missing`);
      required(typeof instruction.bytes === 'string' && /^(?:[a-f0-9]{2})(?: [a-f0-9]{2}){0,14}$/.test(instruction.bytes), `${label}: invalid instruction bytes`);
      const location = BigInt(`0x${instruction.address}`);
      required(previousEnd === null || location >= previousEnd, `${label}: overlapping or unordered instructions`);
      previousEnd = location + BigInt(instruction.bytes.split(' ').length);
      instructionAddresses.add(instruction.address);
      return {address:instruction.address, bytes:instruction.bytes, text:instruction.text};
    });
    required(instructions[0].address === block.start, `${label}: block start does not name its first instruction`);
    required(Array.isArray(block.edges) && block.edges.length <= 32, `${label}: missing or oversized edge list`);
    const targets = new Set();
    const edges = block.edges.map(edge => {
      required(object(edge) && address(edge.to) && text(edge.kind, 64), `${label}: invalid recorded edge`);
      required(!targets.has(`${edge.to}/${edge.kind}`), `${label}: duplicate recorded edge`);
      targets.add(`${edge.to}/${edge.kind}`);
      return {to:edge.to, kind:edge.kind};
    });
    return {start:block.start, instructions, edges};
  });
  required(starts.has(input.entry), `${label}: entry block is missing`);
  required(instructionAddresses.size === input.instruction_count, `${label}: instruction count disagrees with listing`);
  for (const block of blocks) for (const edge of block.edges) required(starts.has(edge.to), `${label}: edge destination is missing`);
  // Exact ownership matters: an instruction must never highlight two blocks.
  const intervals = blocks.flatMap(block => block.instructions.map(i => ({start:BigInt(`0x${i.address}`), end:BigInt(`0x${i.address}`) + BigInt(i.bytes.split(' ').length)})))
    .sort((a,b) => a.start < b.start ? -1 : a.start > b.start ? 1 : 0);
  for (let index=1; index<intervals.length; index++) required(intervals[index].start >= intervals[index-1].end, `${label}: instruction byte ranges overlap`);
  return {name:input.name, entry:input.entry, decompiled_c:input.decompiled_c,
    instruction_count:input.instruction_count, blocks, edge_count:blocks.reduce((sum,b) => sum+b.edges.length,0)};
}

export function validateEvidence(analyses, native, provenance) {
  required(object(analyses) && Object.keys(analyses).length === 2 && BUILDS.every(b => object(analyses[b])), 'Analysis pair: expected O0 and O2');
  required(object(native) && native.schema_version === 1, 'Native record: unsupported schema');
  required(object(provenance) && provenance.schema_version === 1, 'Provenance: unsupported schema');
  const nativeBuilds = twoBuilds(native.builds, 'Native record');
  const artifacts = twoBuilds(provenance.artifacts, 'Provenance');
  const builds = {};
  for (const optimization of BUILDS) {
    const input = analyses[optimization], run = nativeBuilds[optimization];
    required(input.schema_version === 1 && input.program === `fixture-${optimization}.dll`, `${optimization}: schema or program identity differs`);
    required(hash(input.binary_sha256) && input.binary_sha256 === run.sha256 && input.binary_sha256 === artifacts[optimization].sha256, `${optimization}: binary identities disagree`);
    required(text(input.ghidra_version, 80) && input.ghidra_version === provenance.ghidra_version, `${optimization}: analyzer version differs`);
    required(input.language === 'x86:LE:64:default' && input.compiler_spec === 'clangwindows', `${optimization}: analysis target differs`);
    required(Array.isArray(input.functions) && input.functions.length === FUNCTIONS.length, `${optimization}: expected four functions`);
    const functions = {};
    for (const source of input.functions) {
      const fn = functionRecord(source, optimization);
      required(!functions[fn.name], `${optimization}: duplicate function`);
      functions[fn.name] = fn;
    }
    for (const name of FUNCTIONS) required(functions[name], `${optimization}: missing function ${name}`);
    for (const field of ['boolean_inputs','range_inputs','legacy_range_false_accepts','canonical_boolean_errors','bounded_range_errors']) {
      required(count(run[field], field.endsWith('_inputs') ? 1 : 0, 100000000), `${optimization}: missing or invalid native ${field}`);
    }
    builds[optimization] = {optimization, binary_sha256:input.binary_sha256, ghidra_version:input.ghidra_version, functions,
      native:{boolean_inputs:run.boolean_inputs,range_inputs:run.range_inputs,legacy_range_false_accepts:run.legacy_range_false_accepts,
        canonical_boolean_errors:run.canonical_boolean_errors,bounded_range_errors:run.bounded_range_errors}};
  }
  return freeze({builds});
}

export function getFunction(evidence, optimization, name) {
  required(BUILDS.includes(optimization) && FUNCTIONS.includes(name), 'Unknown build or function');
  const fn = evidence?.builds?.[optimization]?.functions?.[name];
  required(fn, `Missing recorded function: ${optimization}/${name}`);
  return fn;
}

export function compareFunction(evidence, name) {
  const builds = Object.fromEntries(BUILDS.map(optimization => {
    const fn = getFunction(evidence, optimization, name);
    return [optimization, {entry:fn.entry,instructions:fn.instruction_count,blocks:fn.blocks.length,edges:fn.edge_count,
      binary_sha256:evidence.builds[optimization].binary_sha256}];
  }));
  return {function:name, builds, delta:{instructions:builds.O2.instructions-builds.O0.instructions,
    blocks:builds.O2.blocks-builds.O0.blocks,edges:builds.O2.edges-builds.O0.edges,entryChanged:builds.O0.entry!==builds.O2.entry}};
}

export function selectBlock(evidence, optimization, name, start) {
  const fn = getFunction(evidence,optimization,name);
  const block = fn.blocks.find(b => b.start===start);
  required(block, `Block is not recorded in ${optimization}/${name}`);
  return freeze({key:JSON.stringify([optimization,name,start]),optimization,function:name,start,
    addresses:block.instructions.map(i => i.address),edges:block.edges.map(e => ({...e}))});
}

export function selectionForView(selection, optimization, name) {
  return selection?.optimization===optimization && selection?.function===name ? selection : null;
}

export function selectedEdge(selection, index) {
  if (!selection || !Number.isSafeInteger(index) || index < 0 || index >= selection.edges.length) return null;
  return {from:selection.start,...selection.edges[index]};
}

export function nextBlockIndex(key, current, length) {
  if (!Number.isSafeInteger(current) || !Number.isSafeInteger(length) || length < 1 || current < 0 || current >= length) return null;
  if (key==='Home') return 0;
  if (key==='End') return length-1;
  if (key==='ArrowDown' || key==='ArrowRight') return (current+1)%length;
  if (key==='ArrowUp' || key==='ArrowLeft') return (current+length-1)%length;
  return null;
}

export function motionAllowed({requested,reduced,visible,inView,edge}) {
  return requested===true && reduced===false && visible===true && inView===true && edge!==null && edge!==undefined;
}
