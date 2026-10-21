/* Optional browser checks: requires Playwright and an installed Edge browser. */
const { chromium } = require('playwright');
const fs = require('node:fs/promises');
const path = require('node:path');
const assert = require('node:assert/strict');

(async () => {
  const browser = await chromium.launch({channel:'msedge', headless:true});
  const context = await browser.newContext({viewport:{width:1440,height:1000}});
  const page = await context.newPage();
  const errors = [], requests = [];
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('request', (request) => requests.push(request.url()));
  const output = path.resolve(__dirname, '../dist/carryglass');
  await fs.mkdir(output, {recursive:true});
  const evidence = {cases:[], widths:[], errors, requests};
  try {
    await page.goto('http://127.0.0.1:8891/carryglass/');
    await page.waitForFunction(() => document.getElementById('record-status').textContent.includes('recorded'));
    const report = JSON.parse(await fs.readFile(path.join(__dirname, 'evidence/report.json'), 'utf8'));
    for (let index = 0; index < report.examples.length; index++) {
      await page.locator('#case').selectOption(String(index));
      const example = report.examples[index];
      const actual = {case:index, sum:await page.locator('#sum').innerText(), low:await page.locator('#low').innerText(),
                      native:await page.locator('#native').innerText(), oracle:await page.locator('#oracle').innerText()};
      assert.equal(actual.sum, example.sum_hex);
      assert.equal(actual.low, example.low32_hex);
      assert.equal(actual.oracle, String(example.expected));
      assert.equal(actual.native, `legacy_range\t${example.native.O0.legacy_range}\t${example.native.O2.legacy_range}\nbounded_range\t${example.native.O0.bounded_range}\t${example.native.O2.bounded_range}`);
      evidence.cases.push(actual);
    }
    await page.locator('#case').selectOption('0');
    await page.locator('#step').click();
    assert.equal(await page.locator('#trace-phase').innerText(), '02 / addition');
    await page.locator('#play').click();
    assert.equal(await page.locator('#play').innerText(), 'Pause trace');
    await page.locator('#play').click();
    assert.equal(await page.locator('#play').innerText(), 'Run trace');
    evidence.traceControls = true;
    await page.screenshot({path:path.join(output,'desktop.png'),fullPage:true});
    for (const width of [1440,390,320]) {
      await page.setViewportSize({width,height:1000});
      const dimensions = await page.evaluate(() => ({viewport:innerWidth,client:document.documentElement.clientWidth,scroll:document.documentElement.scrollWidth}));
      assert.equal(dimensions.scroll, dimensions.client);
      evidence.widths.push(dimensions);
    }
    await page.screenshot({path:path.join(output,'mobile.png'),fullPage:true});
    await page.emulateMedia({reducedMotion:'reduce'});
    await page.waitForFunction(() => document.getElementById('play').disabled);
    assert.equal(await page.locator('#play').isDisabled(), true);
    assert.equal(await page.locator('#play').innerText(), 'Motion off');
    evidence.reducedMotion = true;
    await page.locator('#replay-file').setInputFiles(path.join(__dirname,'evidence/replay.json'));
    await page.waitForFunction(() => document.getElementById('import-status').textContent.includes('Replay values loaded'));
    assert.equal(await page.locator('#sum').innerText(), '0x100000000');
    assert.equal(await page.locator('#native').innerText(), 'legacy_range\t1\t1');
    evidence.replayLoaded = true;
    await page.locator('#replay-file').setInputFiles({name:'bad.json',mimeType:'application/json',buffer:Buffer.from('{"schema":"wrong"}')});
    await page.waitForFunction(() => document.getElementById('import-status').textContent.startsWith('Not loaded:'));
    evidence.malformedRejected = await page.locator('#import-status').innerText();
    assert.equal(await page.locator('#sum').innerText(), '0x100000000');
    assert.equal(errors.length, 0);
    assert(requests.every((url) => url.startsWith('http://127.0.0.1:8891/')));
    evidence.passed = true;
    await fs.writeFile(path.join(output,'browser-check.json'), JSON.stringify(evidence,null,2)+'\n');
    console.log(JSON.stringify(evidence,null,2));
  } finally {
    await context.close();
    await browser.close();
  }
})().catch((error) => { console.error(error); process.exitCode=1; });
