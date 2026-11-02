/* Actual API/browser evidence, invoked only by the isolated fault harness. */
const fs = require('node:fs'), path = require('node:path'), assert = require('node:assert/strict');
const {chromium} = require(process.env.ROYAK_PLAYWRIGHT || 'playwright');
const url = process.env.ROYAK_UI_URL, token = process.env.ROYAK_UI_TOKEN, out = process.env.ROYAK_UI_EVIDENCE;
if (!url || !token || !out) throw Error('Explicit ephemeral lab URL/token/evidence directory required');
(async()=>{
  const browser = await chromium.launch({headless:true});
  try {
    const context = await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:1440,height:1100}});
    const page = await context.newPage(), errors = [];
    page.on('pageerror', e=>errors.push(e.message));
    await context.route('**/*',route=>{
      assert.equal(new URL(route.request().url()).origin,new URL(url).origin,'No external dashboard requests');
      assert.equal(route.request().method(),'GET','Read-only dashboard must not mutate state');
      return route.continue();
    });
    await page.goto(url+'/dashboard'); await page.waitForLoadState('networkidle');
    assert.equal(await page.locator('#status').innerText(),'Not connected');
    await page.getByLabel('Bearer token').fill(token);
    await page.getByLabel('Namespace',{exact:true}).fill('qualification');
    await page.getByRole('button',{name:'Connect / apply scope',exact:true}).click();
    await page.waitForFunction(()=>document.querySelectorAll('#topo-stage .topo-node').length>=3);
    assert.equal(await page.getByLabel('Bearer token').inputValue(),'');
    assert.equal(await page.evaluate(()=>localStorage.length),0);
    const response = await context.request.get(url+'/royak/v1/topology?namespace=qualification',{headers:{Authorization:'Bearer '+token}});
    assert.equal(response.status(),200);
    const graph = await response.json(), pods = graph.nodes.filter(n=>n.kind==='Pod');
    assert.equal(graph.read_only,true); assert.equal(pods.length,3,'Three actual recovered pods');
    assert(pods.every(n=>n.namespace==='qualification'));
    assert(graph.edges.some(e=>e.relation==='runs on' && e.evidence==='observed placement'));
    assert(graph.edges.some(e=>e.relation==='owns'));
    const label = n=>`${n.kind} ${n.namespace || 'cluster'} / ${n.name}, ${n.status}`;
    const podButton = ()=>page.locator('#topo-stage').getByRole('button',{name:label(pods[0]),exact:true});
    await podButton().click();
    assert((await page.locator('#topo-detail').innerText()).includes(pods[0].name));
    assert.match(await page.locator('#topo-detail').innerText(),/observed placement/);
    await page.getByLabel('Find a resource').fill(pods[0].name);
    assert.equal(await page.locator('#topo-stage .topo-node').count(),1);
    await page.getByLabel('Find a resource').fill('');
    await page.getByLabel('Resource kind').selectOption('Pod');
    assert.equal(await page.locator('#topo-stage .topo-node').count(),3);
    await page.getByRole('button',{name:'Reset view',exact:true}).click();
    await podButton().focus(); await page.keyboard.press('Enter');
    // Native detail controls must survive two actual scheduled API polls.
    const connection = page.locator('#topo-detail [data-topo-neighbour]').first();
    await connection.focus();
    const focusKey = await connection.getAttribute('data-topo-neighbour');
    let polls = 0;
    const countPoll = response=>{if(new URL(response.url()).pathname==='/royak/v1/topology') polls++;};
    page.on('response',countPoll);
    await page.waitForFunction(()=>Boolean(document.activeElement?.dataset.topoNeighbour));
    await new Promise(resolve=>{const timer=setInterval(()=>{if(polls>=2){clearInterval(timer);resolve();}},100);setTimeout(()=>{clearInterval(timer);resolve();},16000);});
    page.off('response',countPoll);
    assert(polls>=2,'two real scheduled topology polls');
    assert.equal(await page.evaluate(()=>document.activeElement?.dataset.topoNeighbour),focusKey);
    await page.getByLabel('Namespace',{exact:true}).fill('staged-not-applied');
    assert.match(await page.locator('#topo-session').innerText(),/Changes pending/);
    assert.match(await page.locator('#topo-session').innerText(),/Applied scope: qualification/);
    await page.getByLabel('Namespace',{exact:true}).fill('qualification');
    await page.getByRole('button',{name:'Fit map',exact:true}).click();
    await page.screenshot({path:path.join(out,'topology-desktop.png'),fullPage:true});
    await page.setViewportSize({width:390,height:844});
    await page.getByRole('button',{name:'List view',exact:true}).click();
    assert(await page.locator('#topo-list').isVisible());
    assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
    assert.match(await page.locator('#topo-list').innerText(),/runs on/);
    await page.screenshot({path:path.join(out,'topology-mobile.png'),fullPage:true});
    assert.deepEqual(errors,[]);
    // Qualification evidence must not overwrite the user's existing design
    // review captures. Publishing those is a separate, explicit action.
    if (process.env.ROYAK_UI_UPDATE_REVIEW === '1') {
      const review = path.resolve(__dirname,'../../.impeccable/review'); fs.mkdirSync(review,{recursive:true});
      for (const size of ['desktop','mobile']) fs.copyFileSync(path.join(out,'topology-'+size+'.png'),path.join(review,size+'.png'));
    }
    fs.writeFileSync(path.join(out,'ui-report.json'),JSON.stringify({passed:true,synthetic:false,
      source:'live recovered three-daemon API',namespace:'qualification',pod_count:pods.length,
      node_count:graph.nodes.length,edge_count:graph.edges.length,
      checks:['same-origin GET only','memory-only token','actual recovered pod count','placement/ownership evidence',
              'selection/keyboard','detail focus through two real polls','applied versus staged scope','fit map','search/kind filter','desktop/narrow layout','no script errors'],
      screenshots:['topology-desktop.png','topology-mobile.png']},null,2));
    console.log('PASS live browser: recovered cluster topology, authenticated scoped API, read-only interactions and responsive captures');
  } finally { await browser.close(); }
})().catch(e=>{console.error(String(e.message).split(token).join('[redacted lab token]'));process.exit(1)});
