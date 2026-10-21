import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {BUILDS,FUNCTIONS,validateEvidence,getFunction,compareFunction,selectBlock,selectionForView,selectedEdge,nextBlockIndex,motionAllowed} from './evidence-model.js';

const read = name => JSON.parse(readFileSync(new URL(name,import.meta.url),'utf8'));
const source = {analyses:{O0:read('analysis-O0.json'),O2:read('analysis-O2.json')},native:read('native-tests.json'),provenance:read('provenance.json')};
const load = value => validateEvidence(value.analyses,value.native,value.provenance);
const evidence = load(source);
const altered = change => { const value=structuredClone(source);change(value);return value; };
const fn = value => value.analyses.O0.functions.find(f=>f.name==='canonical_boolean');

test('all eight actual structures retain counts, entries and binary identities',()=>{
 const expected={legacy_boolean:[[9,1,0,'180001000'],[4,1,0,'180001000']],canonical_boolean:[[14,4,4,'180001020'],[5,1,0,'180001010']],legacy_range:[[12,1,0,'180001050'],[5,1,0,'180001020']],bounded_range:[[20,3,3,'180001080'],[7,1,0,'180001030']]};
 for(const name of FUNCTIONS){const comparison=compareFunction(evidence,name);for(const [i,build] of BUILDS.entries()){const row=comparison.builds[build];assert.deepEqual([row.instructions,row.blocks,row.edges,row.entry],expected[name][i]);assert.equal(row.binary_sha256,source.analyses[build].binary_sha256);}assert.equal(comparison.delta.instructions,expected[name][1][0]-expected[name][0][0]);assert.equal(comparison.delta.blocks,expected[name][1][1]-expected[name][0][1]);assert.equal(comparison.delta.edges,expected[name][1][2]-expected[name][0][2]);}
});
test('every recorded block selects exactly its own instruction addresses',()=>{
 for(const build of BUILDS)for(const name of FUNCTIONS){const record=getFunction(evidence,build,name);for(const block of record.blocks){const selected=selectBlock(evidence,build,name,block.start);assert.deepEqual(selected.addresses,block.instructions.map(i=>i.address));assert.equal(selected.key,JSON.stringify([build,name,block.start]));assert.equal(selectionForView(selected,build,name),selected);assert.equal(selectionForView(selected,build==='O0'?'O2':'O0',name),null);assert.equal(selectionForView(selected,build,FUNCTIONS.find(f=>f!==name)),null);for(const [i,edge] of block.edges.entries())assert.deepEqual(selectedEdge(selected,i),{from:block.start,...edge});assert.equal(selectedEdge(selected,-1),null);assert.equal(selectedEdge(selected,block.edges.length),null);}}
});
test('reused entry addresses across builds cannot carry a selection',()=>{
 const selected=selectBlock(evidence,'O0','legacy_boolean','180001000');
 assert.equal(getFunction(evidence,'O2','legacy_boolean').entry,selected.start);
 assert.equal(selectionForView(selected,'O2','legacy_boolean'),null);
 assert.notEqual(selected.key,selectBlock(evidence,'O2','legacy_boolean','180001000').key);
});
test('validated evidence and selections are immutable independent copies',()=>{
 const value=structuredClone(source), model=load(value), selected=selectBlock(model,'O0','canonical_boolean',fn(value).entry);
 value.analyses.O0.functions[0].blocks[0].instructions[0].text='changed';
 assert.notEqual(model.builds.O0.functions.legacy_boolean.blocks[0].instructions[0].text,'changed');
 assert.throws(()=>selected.addresses.push('0'),TypeError);
 assert.throws(()=>model.builds.O0.functions.canonical_boolean.blocks.pop(),TypeError);
});
test('unknown builds, functions and block addresses fail explicitly',()=>{
 assert.throws(()=>getFunction(evidence,'O1','bounded_range'),/Unknown/);
 assert.throws(()=>getFunction(evidence,'O0','other'),/Unknown/);
 assert.throws(()=>selectBlock(evidence,'O0','bounded_range','180001000'),/not recorded/);
});
const badRecords=[
 ['missing analysis',v=>delete v.analyses.O2,/expected O0/],
 ['unsupported schema',v=>v.analyses.O0.schema_version=2,/schema/],
 ['swapped program',v=>v.analyses.O0.program='fixture-O2.dll',/identity/],
 ['mismatched binary',v=>v.analyses.O0.binary_sha256='0'.repeat(64),/identities/],
 ['mismatched native binary',v=>v.native.builds[0].sha256='0'.repeat(64),/identities/],
 ['mismatched provenance binary',v=>v.provenance.artifacts[0].sha256='0'.repeat(64),/identities/],
 ['missing native count',v=>delete v.native.builds[0].range_inputs,/native/],
 ['null native count',v=>v.native.builds[0].bounded_range_errors=null,/native/],
 ['negative native count',v=>v.native.builds[0].bounded_range_errors=-1,/native/],
 ['duplicate build',v=>v.native.builds[1]=v.native.builds[0],/duplicate build/],
 ['missing provenance build',v=>v.provenance.artifacts.pop(),/exactly/],
 ['analyzer mismatch',v=>v.analyses.O0.ghidra_version='other',/version differs/],
 ['target mismatch',v=>v.analyses.O0.language='other',/target differs/],
 ['missing function',v=>v.analyses.O0.functions.pop(),/four functions/],
 ['duplicate function',v=>v.analyses.O0.functions[1]=v.analyses.O0.functions[0],/duplicate function/],
 ['invalid entry',v=>fn(v).entry='not-an-address',/entry/],
 ['unmapped entry',v=>fn(v).entry='1800fffff',/entry block/],
 ['missing recovered C',v=>delete fn(v).decompiled_c,/recovered C/],
 ['missing instruction count',v=>delete fn(v).instruction_count,/instruction count/],
 ['count disagrees with assembly',v=>fn(v).instruction_count+=1,/count disagrees/],
 ['missing blocks',v=>delete fn(v).blocks,/block list/],
 ['duplicate block address',v=>fn(v).blocks.push(fn(v).blocks[0]),/duplicate block/],
 ['empty instructions',v=>fn(v).blocks[0].instructions=[],/block instructions/],
 ['duplicate instruction address',v=>fn(v).blocks[0].instructions[1].address=fn(v).blocks[0].instructions[0].address,/duplicate instruction/],
 ['overlapping instruction bytes',v=>fn(v).blocks[0].instructions[0].bytes=Array(15).fill('ff').join(' '),/overlapping/],
 ['block start mismatch',v=>fn(v).blocks[0].start='1800fffff',/first instruction/],
 ['missing instruction text',v=>delete fn(v).blocks[0].instructions[0].text,/instruction text/],
 ['invalid instruction bytes',v=>fn(v).blocks[0].instructions[0].bytes='zz',/instruction bytes/],
 ['oversized x64 instruction',v=>fn(v).blocks[0].instructions[0].bytes=Array(16).fill('90').join(' '),/instruction bytes/],
 ['missing edge list',v=>delete fn(v).blocks[0].edges,/edge list/],
 ['unknown edge destination',v=>fn(v).blocks[0].edges[0].to='1800fffff',/destination/],
 ['missing edge kind',v=>delete fn(v).blocks[0].edges[0].kind,/recorded edge/],
 ['duplicate edge',v=>fn(v).blocks[0].edges.push(fn(v).blocks[0].edges[0]),/duplicate recorded edge/]
];
for(const [name,change,pattern] of badRecords)test(`rejects ${name} without substituting a zero`,()=>assert.throws(()=>load(altered(change)),pattern));
test('zero outgoing edges are a valid recorded result with no fabricated motion edge',()=>{
 const selected=selectBlock(evidence,'O2','bounded_range','180001030');assert.equal(selected.edges.length,0);assert.equal(selectedEdge(selected,0),null);assert.equal(compareFunction(evidence,'bounded_range').builds.O2.edges,0);
});
test('graph keyboard traversal wraps and respects Home/End',()=>{
 assert.equal(nextBlockIndex('ArrowRight',3,4),0);assert.equal(nextBlockIndex('ArrowLeft',0,4),3);assert.equal(nextBlockIndex('ArrowDown',1,4),2);assert.equal(nextBlockIndex('ArrowUp',1,4),0);assert.equal(nextBlockIndex('Home',3,4),0);assert.equal(nextBlockIndex('End',0,4),3);assert.equal(nextBlockIndex('Enter',0,4),null);assert.equal(nextBlockIndex('ArrowRight',4,4),null);assert.equal(nextBlockIndex('ArrowRight',0,0),null);
});
test('motion requires all four lifecycle gates and a real selected edge',()=>{
 const edge=selectedEdge(selectBlock(evidence,'O0','canonical_boolean','180001020'),0);
 for(const requested of [false,true])for(const reduced of [false,true])for(const visible of [false,true])for(const inView of [false,true])for(const current of [null,edge])assert.equal(motionAllowed({requested,reduced,visible,inView,edge:current}),requested&&!reduced&&visible&&inView&&current!==null);
 assert.equal(motionAllowed({requested:1,reduced:false,visible:true,inView:true,edge}),false);
});
