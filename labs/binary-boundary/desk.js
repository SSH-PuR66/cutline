import {inspectRange,inspectBoolean} from './model.js';
import {validateEvidence,getFunction,compareFunction,selectBlock,selectionForView,selectedEdge,nextBlockIndex,motionAllowed,BUILDS} from './evidence-model.js';
const $=s=>document.querySelector(s), ns='http://www.w3.org/2000/svg';
const choice=$('#function'), buildButtons=[...document.querySelectorAll('button[data-build]')], preference=matchMedia('(prefers-reduced-motion: reduce)');
let evidence=null,optimization='O0',selection=null,edgeIndex=0,requested=false,inView=false,mounted=true;
const requests=new Set();
const notes={bounded_range:'The offset is checked before subtraction. Compare the graph at O0 and O2: the predicate survives a change of shape.',legacy_range:'Unsigned addition wraps at 2³². A comparison after that wrap can approve a range outside the buffer.',canonical_boolean:'Only byte values 0 and 1 are accepted. Every other encoded byte produces the explicit invalid result −1.',legacy_boolean:'The test is nonzero, so all 255 nonzero byte values collapse to the same result.'};
function element(tag,attributes={},text,namespace){const el=namespace?document.createElementNS(namespace,tag):document.createElement(tag);for(const [key,value] of Object.entries(attributes))el.setAttribute(key,String(value));if(text!==undefined)el.textContent=text;return el;}
const svg=(tag,attributes,text)=>element(tag,attributes,text,ns);
const currentSelection=()=>selectionForView(selection,optimization,choice.value);
function motion(){
 const edge=selectedEdge(currentSelection(),edgeIndex),on=motionAllowed({requested,reduced:preference.matches,visible:!document.hidden&&mounted,inView,edge});
 document.body.dataset.motion=on?'on':'off';
 $('#motion').textContent=preference.matches?'Trace / reduced motion':!edge?'Trace / select an edge':on?'Pause edge illustration':requested?'Trace / suspended':'Illustrate selected edge';
 $('#motion').setAttribute('aria-pressed',String(on));$('#motion').disabled=!evidence||preference.matches||!edge;
 $('#trace-state').textContent=on?'Illustrating one recorded edge. This is not a live execution trace.':edge?'Still edge selection. Motion is an illustration of the recorded destination.':'Select a block with outgoing edges to illustrate one recorded connection.';
}
function compare(name){
 const {builds,delta}=compareFunction(evidence,name),signed=value=>value>0?`+${value}`:String(value);
 const rows=[['Instructions',builds.O0.instructions,builds.O2.instructions,signed(delta.instructions)],['Basic blocks',builds.O0.blocks,builds.O2.blocks,signed(delta.blocks)],['Recorded edges',builds.O0.edges,builds.O2.edges,signed(delta.edges)],['Entry address',builds.O0.entry,builds.O2.entry,delta.entryChanged?'moved':'same']];
 $('#comparison-rows').replaceChildren(...rows.map(values=>{const tr=element('tr');values.forEach((value,index)=>tr.append(element(index===0?'th':'td',index===0?{scope:'row'}:{},value)));return tr;}));
 $('#comparison-title').textContent=`${name} / O0 → O2`;
 $('#binary-identities').replaceChildren(...BUILDS.map(build=>{const div=element('div');div.append(element('dt',{},`${build} / SHA-256`),element('dd',{},builds[build].binary_sha256));return div;}));
}
function renderListing(fn){
 const fragment=document.createDocumentFragment();
 for(const block of fn.blocks)for(const instruction of block.instructions)fragment.append(element('span',{class:'assembly-line','data-build':optimization,'data-function':fn.name,'data-block':block.start,'data-address':instruction.address},`${instruction.address}  ${instruction.bytes.padEnd(26)}  ${instruction.text}`),document.createTextNode('\n'));
 $('#assembly').replaceChildren(fragment);
}
function updateSelection(){
 const active=currentSelection(),edge=selectedEdge(active,edgeIndex);
 for(const group of document.querySelectorAll('.graph-node')){const selected=group.dataset.block===active?.start;group.classList.toggle('is-selected',selected);group.setAttribute('aria-pressed',String(selected));group.setAttribute('tabindex',selected||(!active&&group.dataset.entry==='true')?'0':'-1');}
 const addresses=new Set(active?.addresses||[]);
 for(const line of document.querySelectorAll('.assembly-line'))line.classList.toggle('is-selected',Boolean(active&&line.dataset.build===active.optimization&&line.dataset.function===active.function&&addresses.has(line.dataset.address)));
 for(const path of document.querySelectorAll('.flow-edge'))path.classList.toggle('is-selected',Boolean(edge&&path.dataset.from===edge.from&&path.dataset.to===edge.to&&path.dataset.kind===edge.kind));
 $('#assembly').dataset.selectionKey=active?.key||'';
 $('#block-summary').textContent=active?`${active.optimization} / ${active.function} / ${active.start} · ${active.addresses.length} recorded instruction${active.addresses.length===1?'':'s'} selected`:'No block selected. Tab into the graph; arrows move focus, Enter or Space selects, Escape clears.';
 $('#block-addresses').textContent=active?active.addresses.join(' · '):'—';$('#clear-selection').disabled=!active;
 $('#edge-choice').replaceChildren(...(active?.edges.length?active.edges.map((item,index)=>element('option',{value:index},`${item.kind} → ${item.to}`)):[element('option',{value:''},active?'No outgoing edge recorded':'Select a block first')]));
 $('#edge-choice').disabled=!active?.edges.length;if(active?.edges.length)$('#edge-choice').value=String(edgeIndex);motion();
}
function chooseBlock(start){requested=false;selection=selectBlock(evidence,optimization,choice.value,start);edgeIndex=0;updateSelection();}
function clearSelection(){selection=null;edgeIndex=0;requested=false;updateSelection();}
function graph(fn){
 const flow=$('#flow');flow.replaceChildren(svg('title',{id:'flow-title'},`${fn.name}: recorded control-flow graph`),svg('desc',{id:'flow-desc'},`${fn.blocks.length} selectable basic blocks. Arrows move focus; Enter or Space selects exact assembly lines. Escape clears selection.`));
 const defs=svg('defs'),marker=svg('marker',{id:'arrow',viewBox:'0 0 10 10',refX:9,refY:5,markerWidth:5,markerHeight:5,orient:'auto-start-reverse'});marker.append(svg('path',{d:'M0 0L10 5L0 10Z',fill:'#d87866'}));defs.append(marker);flow.append(defs);
 const blocks=fn.blocks,depth=new Map(),order=new Map(blocks.map((b,i)=>[b.start,i]));
 // Forward edges establish editorial layers; every recorded edge is still drawn.
 blocks.forEach((b,i)=>{if(!depth.has(b.start))depth.set(b.start,0);for(const edge of b.edges)if(order.get(edge.to)>i)depth.set(edge.to,Math.max(depth.get(edge.to)||0,depth.get(b.start)+1));});
 const levels=new Map();for(const block of blocks){const d=depth.get(block.start);if(!levels.has(d))levels.set(d,[]);levels.get(d).push(block);}
 const positions=new Map(),width=660,height=Math.max(220,(Math.max(...levels.keys())+1)*142+32);flow.setAttribute('viewBox',`0 0 ${width} ${height}`);
 for(const [level,list] of levels)list.forEach((b,i)=>positions.set(b.start,{x:width/(list.length+1)*(i+1),y:35+level*142}));
 for(const b of blocks)for(const edge of b.edges){const a=positions.get(b.start),z=positions.get(edge.to),side=z.y<=a.y||z.y-a.y>160&&Math.abs(z.x-a.x)<20;
  const d=side?`M${a.x+91} ${a.y+35} C${a.x+220} ${a.y+35},${z.x+220} ${z.y+35},${z.x+91} ${z.y+35}`:`M${a.x} ${a.y+69} C${a.x} ${a.y+105},${z.x} ${z.y-25},${z.x} ${z.y}`;
  flow.append(svg('path',{d,class:'flow-edge','marker-end':'url(#arrow)','data-from':b.start,'data-to':edge.to,'data-kind':edge.kind}));flow.append(svg('text',{x:side?a.x+155:(a.x+z.x)/2+7,y:(a.y+z.y)/2+33,class:'edge-label'},edge.kind));}
 blocks.forEach((b,index)=>{const p=positions.get(b.start),group=svg('g',{class:`graph-node${b.start===fn.entry?' is-entry':''}`,role:'button',tabindex:b.start===fn.entry?'0':'-1','aria-pressed':'false','aria-label':`${optimization} ${fn.name}, block ${b.start}, ${b.instructions.length} recorded instructions`,'data-block':b.start,'data-entry':String(b.start===fn.entry)});
  group.append(svg('rect',{x:p.x-91,y:p.y,width:182,height:70,rx:1}),svg('text',{x:p.x-75,y:p.y+24},b.start),svg('text',{x:p.x-75,y:p.y+47,class:'node-count'},`${b.instructions.length} instructions · ${b.instructions.at(-1).text.split(' ')[0]}`));
  group.addEventListener('click',()=>chooseBlock(b.start));group.addEventListener('keydown',event=>{
   if(event.key==='Enter'||event.key===' '){event.preventDefault();chooseBlock(b.start);return;}
   if(event.key==='Escape'){event.preventDefault();clearSelection();group.focus();return;}
   const next=nextBlockIndex(event.key,index,blocks.length);if(next!==null){event.preventDefault();const groups=flow.querySelectorAll('.graph-node');groups.forEach(g=>g.setAttribute('tabindex','-1'));groups[next].setAttribute('tabindex','0');groups[next].focus();}
  });flow.append(group);
 });$('#graph-count').textContent=`${blocks.length} BLOCK${blocks.length===1?'':'S'}`;
}
function inspect(){
 if(!evidence)return;const isBoolean=choice.value.includes('boolean');$('#range-inputs').hidden=isBoolean;$('#boolean-inputs').hidden=!isBoolean;$('#challenge-explanation').textContent=isBoolean?'A nonzero byte and a canonical Boolean encoding answer different questions. The corrected decoder returns −1 for invalid encodings.':'Unsigned addition can wrap before the comparison. The corrected predicate bounds the offset before subtraction.';
 try{const result=isBoolean?inspectBoolean($('#byte').value):inspectRange($('#total').value,$('#offset').value,$('#count').value);$('#input-error').textContent='';$('#legacy-result').textContent=isBoolean?String(result.legacy):(result.legacy?'ACCEPT':'REJECT');$('#corrected-result').textContent=result.corrected===-1?'INVALID':isBoolean?String(result.corrected):(result.corrected?'ACCEPT':'REJECT');$('#arithmetic').textContent=isBoolean?`Encoded byte ${$('#byte').value} → nonzero predicate ${result.legacy}; canonical result ${result.corrected}.`:`Exact sum: ${result.sum} · uint32 sum: ${result.wrapped}`;}catch(error){$('#input-error').textContent=error.message;$('#legacy-result').textContent='—';$('#corrected-result').textContent='—';$('#arithmetic').textContent='Enter a valid unsigned value to evaluate.';}
}
function render(){const fn=getFunction(evidence,optimization,choice.value);selection=null;edgeIndex=0;requested=false;$('#function-note').textContent=notes[fn.name];$('#decompiled').textContent=fn.decompiled_c.trim();$('#entry').textContent=fn.entry;$('#instruction-count').textContent=`${fn.instruction_count} INSTRUCTIONS`;buildButtons.forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.build===optimization)));compare(fn.name);renderListing(fn);graph(fn);updateSelection();inspect();}
async function json(path){
 const controller=new AbortController();requests.add(controller);const timeout=setTimeout(()=>controller.abort(),10000);let reader;
 try{const response=await fetch(path,{signal:controller.signal});if(!response.ok)throw new Error(`Report unavailable (${response.status})`);const limit=1024*1024,declared=Number(response.headers.get('content-length'));if(Number.isFinite(declared)&&declared>limit)throw new Error('Recorded JSON exceeds the 1 MiB limit');reader=response.body.getReader();let length=0;const chunks=[];
  while(true){const {done,value}=await reader.read();if(done)break;length+=value.length;if(length>limit)throw new Error('Recorded JSON exceeds the 1 MiB limit');chunks.push(value);}
  const bytes=new Uint8Array(length);let at=0;for(const chunk of chunks){bytes.set(chunk,at);at+=chunk.length;}return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
 }catch(error){await reader?.cancel().catch(()=>{});throw error;}finally{reader?.releaseLock();clearTimeout(timeout);requests.delete(controller);}
}
async function start(){
 try{const [o0,o2,native,provenance]=await Promise.all(['analysis-O0.json','analysis-O2.json','native-tests.json','provenance.json'].map(json));if(!mounted)return;evidence=validateEvidence({O0:o0,O2:o2},native,provenance);
  $('#ghidra-version').textContent=evidence.builds.O0.ghidra_version;const accepts=BUILDS.map(b=>evidence.builds[b].native.legacy_range_false_accepts);$('#false-accepts').textContent=accepts[0]===accepts[1]?accepts[0].toLocaleString():accepts.map((n,i)=>`${BUILDS[i]} ${n.toLocaleString()}`).join(' / ');$('#corrected-errors').textContent=BUILDS.reduce((sum,b)=>sum+evidence.builds[b].native.canonical_boolean_errors+evidence.builds[b].native.bounded_range_errors,0);$('#provenance').textContent=JSON.stringify(provenance,null,2);
  for(const b of BUILDS){const run=evidence.builds[b].native,tr=element('tr');for(const value of [b,run.boolean_inputs,run.range_inputs,run.legacy_range_false_accepts,run.canonical_boolean_errors+run.bounded_range_errors])tr.append(element('td',{},typeof value==='number'?value.toLocaleString():value));$('#test-rows').append(tr);}
  choice.disabled=false;buildButtons.forEach(b=>b.disabled=false);$('#report-status').textContent='RECORDED ANALYSIS / STRUCTURE + IDENTITIES MATCH';document.body.dataset.report='verified';render();
 }catch(error){evidence=null;selection=null;requested=false;$('#report-status').textContent='ANALYSIS UNAVAILABLE';document.body.dataset.report='error';$('#decompiled').textContent=error.message;$('#function-note').textContent='The source links remain available. Recorded structure and identities could not be verified.';$('#comparison-rows').replaceChildren();$('#binary-identities').replaceChildren();motion();}
}
choice.addEventListener('change',render);buildButtons.forEach(b=>b.addEventListener('click',()=>{optimization=b.dataset.build;render();}));document.querySelectorAll('.inputs input').forEach(i=>i.addEventListener('input',inspect));
$('#reset-inputs').addEventListener('click',()=>{$('#total').value='16';$('#offset').value='4294967295';$('#count').value='2';$('#byte').value='2';inspect();});
$('#clear-selection').addEventListener('click',clearSelection);$('#edge-choice').addEventListener('change',()=>{edgeIndex=Number($('#edge-choice').value);requested=false;updateSelection();});$('#motion').addEventListener('click',()=>{requested=!requested;motion();});
preference.addEventListener('change',()=>{requested=false;motion();});document.addEventListener('visibilitychange',motion);
addEventListener('pagehide',()=>{mounted=false;requested=false;motion();for(const controller of requests)controller.abort();});addEventListener('pageshow',()=>{mounted=true;motion();});
new IntersectionObserver(([entry])=>{inView=entry.isIntersecting;motion();},{threshold:0.01}).observe($('#flow'));start();
