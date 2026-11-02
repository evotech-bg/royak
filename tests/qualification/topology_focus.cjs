/* Supplemental real polling evidence; only an owned qualification node. */
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {execFileSync}=require('node:child_process');
const {chromium}=require(process.env.ROYAK_PLAYWRIGHT||'playwright');
const directory=path.resolve(process.argv[2]||'');
const manifest=JSON.parse(fs.readFileSync(path.join(directory,'manifest.json'),'utf8'));
assert(/^rkq-\d{8}-\d{6}-[a-f0-9]+$/.test(manifest.run_id));
assert([1,2,3].includes(manifest.nodes[0].id));
const owned=manifest.run_id+'-n'+manifest.nodes[0].id;
const inspected=JSON.parse(execFileSync('docker',['inspect',owned],{encoding:'utf8'}))[0];
assert.equal(inspected.Config.Labels['royak.qualification'],manifest.run_id);
const mount=inspected.Mounts.find(m=>m.Destination==='/opt/royak');
assert(mount&&!mount.RW);
const sha=file=>crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
assert.equal(sha(mount.Source),manifest.binary_sha256);
for(const file of ['src/dashboard.html','src/dashboard.css','src/dashboard-topology.js'])
  assert.equal(sha(path.resolve(__dirname,'../..',file)),manifest.source_sha256[file]);
const token=inspected.Config.Env.find(e=>e.startsWith('ROYAK_TOKEN=')).slice('ROYAK_TOKEN='.length);
const port=Number(inspected.NetworkSettings.Ports['6443/tcp'][0].HostPort);
assert(port>0&&port<=65535);
const url='https://127.0.0.1:'+port;
(async()=>{
  const browser=await chromium.launch({headless:true});
  try{
    const context=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:1440,height:1100}});
    const page=await context.newPage();
    await page.route('**/*',route=>{assert.equal(new URL(route.request().url()).origin,url);assert.equal(route.request().method(),'GET');return route.continue();});
    await page.goto(url+'/dashboard');await page.waitForLoadState('networkidle');
    await page.getByLabel('Bearer token').fill(token);await page.getByLabel('Namespace',{exact:true}).fill('qualification');
    await page.getByRole('button',{name:'Connect / apply scope',exact:true}).click();
    await page.locator('#topo-stage .topo-node').first().waitFor();
    const pod=page.locator('#topo-stage .topo-node').filter({hasText:'Pod · qualification'}).first();await pod.click();
    const keys=await page.locator('#topo-detail [data-topo-neighbour]').evaluateAll(buttons=>buttons.map(b=>b.dataset.topoNeighbour));
    assert(keys.length>=3,'ownership, service and node connections');
    for(const key of keys){
      await page.evaluate(key=>[...document.querySelectorAll('#topo-detail [data-topo-neighbour]')].find(b=>b.dataset.topoNeighbour===key).focus(),key);
      for(let i=0;i<2;i++) await page.waitForResponse(r=>new URL(r.url()).pathname==='/royak/v1/topology'&&r.status()===200,{timeout:9000});
      await page.waitForFunction(key=>document.activeElement?.dataset.topoNeighbour===key,key);
      assert.equal(await page.evaluate(()=>document.activeElement?.dataset.topoNeighbour),key);
    }
    fs.writeFileSync(path.join(directory,'ui-focus-report.json'),JSON.stringify({passed:true,synthetic:false,binary_sha256:manifest.binary_sha256,
      fixture_sha256:sha(__filename),source:'owned recovered three-daemon node; same-origin GET only',connections_checked:keys.length,
      scheduled_polls_per_connection:2,credentials_exported:false},null,2));
    console.log('PASS real focus: every selected pod connection retained keyboard focus through two scheduled polls');
  }finally{await browser.close();}
})().catch(e=>{console.error(String(e.message).split(token).join('[redacted lab token]'));process.exit(1);});
