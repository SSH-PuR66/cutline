/* Optional integration checks: Playwright plus an installed Edge browser. */
const {chromium}=require('playwright');
const fs=require('node:fs/promises');
const path=require('node:path');
const assert=require('node:assert/strict');
const {createHash}=require('node:crypto');
const origin=process.env.FAULTLINE_ORIGIN||'http://127.0.0.1:8891';
const url=`${origin}/labs/binary-boundary/`;
const read=async name=>JSON.parse(await fs.readFile(path.join(__dirname,name),'utf8'));

(async()=>{
 const browser=await chromium.launch({channel:'msedge',headless:true});
 const context=await browser.newContext({viewport:{width:1440,height:1000},reducedMotion:'no-preference'});
 const page=await context.newPage();
 const errors=[],requests=[];page.on('pageerror',error=>errors.push(error.message));page.on('request',request=>requests.push(request.url()));
 const output=path.resolve(__dirname,'../../dist/recorded-structure');await fs.mkdir(output,{recursive:true});
 const records={O0:await read('analysis-O0.json'),O2:await read('analysis-O2.json')};
 const report={schema_version:1,recorded_at:new Date().toISOString(),browser:browser.version(),node:process.version,structures:[],selection_checks:[],lifecycle:[],widths:[],rejections:[],source_sha256:{},page_errors:errors,external_requests:[]};
 const selectedAddresses=()=>page.locator('.assembly-line.is-selected').evaluateAll(lines=>lines.map(line=>line.dataset.address));
 const motionState=state=>page.waitForFunction(expected=>document.body.dataset.motion===expected,state);
 try{
  await page.goto(url);await page.waitForFunction(()=>document.body.dataset.report==='verified');
  assert.equal(await page.locator('.worm-specimen img').evaluate(image=>image.complete&&image.naturalWidth>0),true);
  for(const build of ['O0','O2'])for(const fn of records[build].functions){
   await page.locator(`button[data-build="${build}"]`).click();await page.locator('#function').selectOption(fn.name);
   assert.deepEqual(await selectedAddresses(),[]);assert.equal(await page.locator('#assembly').getAttribute('data-selection-key'),'');
   assert.equal(await page.locator('.graph-node').count(),fn.blocks.length);
   const expectedEdges=fn.blocks.reduce((sum,b)=>sum+b.edges.length,0);assert.equal(await page.locator('.flow-edge').count(),expectedEdges);
   const expected=Object.fromEntries(['O0','O2'].map(b=>{const f=records[b].functions.find(item=>item.name===fn.name);return[b,{instructions:f.instruction_count,blocks:f.blocks.length,edges:f.blocks.reduce((sum,x)=>sum+x.edges.length,0),entry:f.entry,sha256:records[b].binary_sha256}];}));
   const cells=await page.locator('#comparison-rows tr').evaluateAll(rows=>rows.map(row=>[...row.children].map(cell=>cell.textContent)));
   for(const [index,field] of ['instructions','blocks','edges','entry'].entries()){assert.equal(cells[index][1],String(expected.O0[field]));assert.equal(cells[index][2],String(expected.O2[field]));}
   for(const buildName of ['O0','O2'])assert.ok((await page.locator('#binary-identities').innerText()).includes(expected[buildName].sha256));
   report.structures.push({build,function:fn.name,...expected[build]});
   for(const [index,block] of fn.blocks.entries()){
    const node=page.locator(`.graph-node[data-block="${block.start}"]`),addresses=block.instructions.map(i=>i.address);
    await node.click();assert.deepEqual(await selectedAddresses(),addresses);assert.equal(await node.getAttribute('aria-pressed'),'true');assert.equal(await page.locator('#assembly').getAttribute('data-selection-key'),JSON.stringify([build,fn.name,block.start]));
    assert.equal(await page.locator('#edge-choice').isDisabled(),block.edges.length===0);
    for(const [edgeIndex,edge] of block.edges.entries()){
     await page.locator('#edge-choice').selectOption(String(edgeIndex));
     assert.deepEqual(await page.locator('.flow-edge.is-selected').evaluateAll(paths=>paths.map(item=>({from:item.dataset.from,to:item.dataset.to,kind:item.dataset.kind}))),[{from:block.start,...edge}]);
    }
    await node.focus();await node.press('Escape');assert.deepEqual(await selectedAddresses(),[]);
    await node.press('Enter');assert.deepEqual(await selectedAddresses(),addresses);
    await node.press('Escape');await node.press('Space');assert.deepEqual(await selectedAddresses(),addresses);
    await node.press('ArrowRight');assert.equal(await page.evaluate(()=>document.activeElement.dataset.block),fn.blocks[(index+1)%fn.blocks.length].start);
    await page.keyboard.press('Home');assert.equal(await page.evaluate(()=>document.activeElement.dataset.block),fn.blocks[0].start);
    await page.keyboard.press('End');assert.equal(await page.evaluate(()=>document.activeElement.dataset.block),fn.blocks.at(-1).start);
    report.selection_checks.push({build,function:fn.name,block:block.start,addresses,click:true,enter:true,space:true,escape:true,arrows:true,home_end:true,edges:block.edges.length});
   }
  }
  // Same function and same entry address, different binary: selection still resets.
  await page.locator('#function').selectOption('legacy_boolean');await page.locator('button[data-build="O0"]').click();await page.locator('.graph-node').click();await page.locator('button[data-build="O2"]').click();assert.deepEqual(await selectedAddresses(),[]);report.lifecycle.push('same-address build switch resets selection');
  await page.locator('button[data-build="O0"]').click();await page.locator('#function').selectOption('canonical_boolean');await page.locator('.graph-node').first().click();
  await page.locator('#motion').click();await motionState('on');
  const animations=await page.locator('.flow-edge').evaluateAll(paths=>paths.map(p=>({selected:p.classList.contains('is-selected'),animation:getComputedStyle(p).animationName})));
  assert.equal(animations.filter(a=>a.animation==='trace').length,1);assert.ok(animations.every(a=>a.selected||a.animation==='none'));
  report.lifecycle.push('only selected recorded edge animates after opt-in');
  await page.locator('#motion').click();await motionState('off');report.lifecycle.push('pause stops animation');
  await page.locator('#motion').click();await motionState('on');
  await page.locator('footer').scrollIntoViewIfNeeded();await motionState('off');
  await page.locator('#flow').scrollIntoViewIfNeeded();await motionState('on');report.lifecycle.push('offscreen suspend and visible resume');
  await page.evaluate(()=>{Object.defineProperty(document,'hidden',{configurable:true,value:true});document.dispatchEvent(new Event('visibilitychange'));});await motionState('off');
  await page.evaluate(()=>{delete document.hidden;document.dispatchEvent(new Event('visibilitychange'));});await motionState('on');report.lifecycle.push('visibilitychange handler suspends (simulated hidden property)');
  await page.emulateMedia({reducedMotion:'reduce'});await motionState('off');await page.waitForFunction(()=>document.querySelector('#motion').disabled);assert.equal(await page.locator('.flow-edge.is-selected').evaluate(p=>getComputedStyle(p).animationName),'none');
  await page.emulateMedia({reducedMotion:'no-preference'});await page.waitForFunction(()=>!document.querySelector('#motion').disabled);await motionState('off');report.lifecycle.push('reduced-motion change stops and revokes opt-in');
  await page.locator('#motion').click();await motionState('on');await page.evaluate(()=>dispatchEvent(new PageTransitionEvent('pagehide')));await motionState('off');await page.evaluate(()=>dispatchEvent(new PageTransitionEvent('pageshow')));await motionState('off');report.lifecycle.push('pagehide stops; pageshow requires fresh opt-in');
  await page.locator('#motion').click();await motionState('on');await page.locator('#edge-choice').selectOption('1');await motionState('off');report.lifecycle.push('edge switch revokes opt-in');
  await page.locator('#function').selectOption('bounded_range');assert.deepEqual(await selectedAddresses(),[]);await motionState('off');report.lifecycle.push('function switch resets selection and motion');
  await page.locator('.graph-node').last().click();assert.equal(await page.locator('#motion').isDisabled(),true);report.lifecycle.push('terminal block cannot animate an invented edge');
  await page.locator('.graph-node').first().click();await page.locator('#clear-selection').click();assert.deepEqual(await selectedAddresses(),[]);assert.equal(await page.locator('#motion').isDisabled(),true);report.lifecycle.push('clear selection disables trace');
  await page.locator('.graph-node').first().click();await page.locator('#flow').scrollIntoViewIfNeeded();await page.screenshot({path:path.join(output,'desktop-selection.png'),fullPage:false});
  await page.locator('.structure-compare').scrollIntoViewIfNeeded();await page.screenshot({path:path.join(output,'desktop-comparison.png'),fullPage:false});
  for(const width of [320,390,768,1440]){await page.setViewportSize({width,height:900});await page.locator('.structure-compare').scrollIntoViewIfNeeded();const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth);assert.equal(overflow,false,`page overflow at ${width}px`);report.widths.push({width,page_overflow:false});if(width===390)await page.screenshot({path:path.join(output,'mobile-comparison.png'),fullPage:false});}
  for(const [label,change,status] of [
   ['missing report',null,404],
   ['malformed JSON','{',200],
   ['binary identity mismatch',{...records.O2,binary_sha256:'0'.repeat(64)},200],
   ['missing instruction count',{...records.O2,functions:records.O2.functions.map((fn,i)=>i?fn:{...fn,instruction_count:null})},200],
   ['oversized report',' '.repeat(1024*1024+1),200]
  ]){
   const broken=await context.newPage();broken.on('pageerror',error=>errors.push(error.message));await broken.route('**/analysis-O2.json',route=>route.fulfill({status,contentType:'application/json',body:typeof change==='string'?change:JSON.stringify(change)}));await broken.goto(url);await broken.waitForFunction(()=>document.body.dataset.report==='error');assert.equal(await broken.locator('#function').isDisabled(),true);assert.equal(await broken.locator('#comparison-rows tr').count(),0);assert.equal(await broken.locator('#false-accepts').innerText(),'—');assert.equal(await broken.locator('#motion').isDisabled(),true);report.rejections.push({case:label,status:'rejected',message:await broken.locator('#decompiled').innerText()});await broken.close();
  }
  for(const name of ['evidence-model.js','desk.js','desk.css','index.html','test-evidence-model.mjs','check-structure-browser.cjs','analysis-O0.json','analysis-O2.json','native-tests.json','provenance.json','../../assets/faultline-worm.png'])report.source_sha256[name]=createHash('sha256').update(await fs.readFile(path.join(__dirname,name))).digest('hex');
  report.external_requests=requests.filter(request=>!request.startsWith(origin+'/'));assert.deepEqual(report.external_requests,[]);assert.deepEqual(errors,[]);
  await fs.writeFile(path.join(output,'browser-check.json'),JSON.stringify(report,null,2)+'\n');
  console.log(JSON.stringify({structures:report.structures.length,block_selections:report.selection_checks.length,lifecycle:report.lifecycle.length,widths:report.widths.length,rejections:report.rejections.length,page_errors:errors.length,external_requests:report.external_requests.length,report:path.join(output,'browser-check.json')},null,2));
 }finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
