/* Read-only topology client. All API data is rendered as text, never markup. */
(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  let token = '', namespace = '', active = false, epoch = 0, request = null;
  let graph = null, selected = '', zoom = 1, listMode = matchMedia('(max-width: 800px)').matches;
  let busy = false, lastSuccess = 0;
  let baseMessage = 'Connect to load actual cluster resources.';
  const positions = new Map();
  const columns = ['Ingress', 'Service', 'Workload', 'Pod', 'Node', 'Dependencies'];
  const col = kind => kind === 'Ingress' ? 0 : kind === 'Service' ? 1 : ['Deployment','StatefulSet','DaemonSet','Job','CronJob','Workload'].includes(kind) ? 2 : kind === 'Pod' ? 3 : kind === 'Node' ? 4 : 5;
  const el = (tag, text, cls) => { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (cls) n.className = cls; return n; };
  const headers = () => token ? {Authorization: `Bearer ${token}`} : {};
  window.RoyakSession = Object.freeze({active: () => active, epoch: () => epoch, headers,
    path: path => {
      if (!namespace) return path;
      const core = path.match(/^\/api\/v1\/(pods|services|events|configmaps|secrets)(?:[/?]|$)/);
      const apps = path.match(/^\/apis\/apps\/v1\/(deployments|replicasets|statefulsets|daemonsets)(?:[/?]|$)/);
      return core ? path.replace('/api/v1/', `/api/v1/namespaces/${encodeURIComponent(namespace)}/`)
        : apps ? path.replace('/apis/apps/v1/', `/apis/apps/v1/namespaces/${encodeURIComponent(namespace)}/`) : path;
    }});
  function sessionStatus() {
    const pending = active && ($('topo-namespace').value.trim() !== namespace || Boolean($('topo-token').value));
    $('topo-session').textContent = active
      ? `Applied scope: ${namespace || 'cluster-wide'}. ${token ? 'Token retained in memory; blank token reuses it.' : 'No bearer token retained.'}${pending ? ' Changes pending — press Connect / apply scope. Data still belongs to the applied scope.' : ''}`
      : 'No applied session. Enter a token and apply a scope to load resources.';
  }
  function message(text) { baseMessage = text; $('topo-message').textContent = text; }
  function clearData() {
    graph = null; selected = ''; positions.clear();
    $('topo-stage').replaceChildren(); $('topo-list').replaceChildren(); $('topo-warning-list').replaceChildren();
    $('topo-detail').replaceChildren(el('h3', 'Inspect a resource'), el('p', 'Select a node or use the list to inspect its relationships.'));
    $('topo-count').textContent = 'No data loaded'; $('topo-time').textContent = 'Not observed';
    for (const id of ['pods-table','deploys-grid','events-list']) $(id).replaceChildren();
    for (const id of ['pods-empty','deploys-empty','events-empty']) { $(id).textContent = 'Data not loaded in this session'; $(id).classList.remove('hidden'); }
    for (const id of ['stat-pods','stat-deploys','stat-services','stat-ns','stat-loss','stat-certs','brain-steps','brain-loss','brain-anomalies','ca-fp','net-count','audit-count','brain-status']) $(id).textContent = '—';
  }
  function select(id, focusDetails = false) {
    selected = id;
    decorate(); detail();
    if (focusDetails) { $('topo-detail').tabIndex = -1; $('topo-detail').focus({preventScroll: true}); }
  }
  function detail(preserveFocus = false) {
    const panel = $('topo-detail');
    const focusKey = preserveFocus && panel.contains(document.activeElement) ? document.activeElement.dataset.topoNeighbour : null;
    const restore = () => {
      if (!focusKey) return;
      const replacement = [...panel.querySelectorAll('[data-topo-neighbour]')].find(button => button.dataset.topoNeighbour === focusKey);
      if (replacement) replacement.focus({preventScroll: true});
      else { panel.tabIndex = -1; panel.focus({preventScroll: true}); const notice = el('p', 'The focused connection is no longer in this snapshot. Choose another connection.'); notice.setAttribute('role','status'); panel.append(notice); }
    };
    panel.replaceChildren();
    const node = graph?.nodes.find(n => n.id === selected);
    if (!node) { panel.append(el('h3', selected ? 'Resource no longer observed' : 'Inspect a resource'), el('p', selected ? 'It may have been removed, filtered by permission or lost from the current census. Select another resource.' : 'Select a resource to see its state, evidence and connections.')); restore(); return; }
    panel.append(el('h3', node.name), el('p', `${node.kind} · ${node.namespace || 'cluster-scoped'} · ${node.status}`), el('p', node.evidence));
    const facts = el('dl'); for (const [key, value] of node.facts) facts.append(el('dt', key), el('dd', value)); panel.append(facts);
    const edges = graph.edges.filter(e => e.from === selected || e.to === selected);
    panel.append(el('h3', `Connections (${edges.length})`));
    const list = el('ul');
    for (const edge of edges) {
      const target = graph.nodes.find(n => n.id === (edge.from === selected ? edge.to : edge.from)); if (!target) continue;
      const li = el('li'); const button = el('button', `${edge.from === selected ? 'To' : 'From'} ${target.kind} ${target.namespace ? target.namespace + '/' : ''}${target.name}`, 'topo-neighbour');
      button.dataset.topoNeighbour = JSON.stringify([selected, edge.from, edge.to, edge.relation]);
      button.type = 'button'; button.addEventListener('click', () => select(target.id, true));
      li.append(button, el('p', `${edge.relation} — ${edge.evidence}`)); list.append(li);
    }
    if (!edges.length) list.append(el('li', 'No relationships observed in this snapshot.'));
    panel.append(list);
    restore();
  }
  function neighbours() {
    const ids = new Set([selected]); for (const e of graph?.edges || []) if (e.from === selected || e.to === selected) { ids.add(e.from); ids.add(e.to); } return ids;
  }
  function decorate() {
    const ids = neighbours();
    for (const button of document.querySelectorAll('[data-topo-id]')) {
      const id = button.dataset.topoId; button.classList.toggle('selected', id === selected); button.classList.toggle('related', Boolean(selected) && ids.has(id)); button.setAttribute('aria-pressed', String(id === selected));
    }
    for (const path of $('topo-stage').querySelectorAll('path')) { const match = path.dataset.from === selected || path.dataset.to === selected; path.classList.toggle('related', Boolean(selected) && match); path.classList.toggle('muted', Boolean(selected) && !match); }
  }
  function buttonFor(node, map) {
    const button = el('button', undefined, map ? 'topo-node' : 'topo-neighbour'); button.type = 'button'; button.dataset.topoId = node.id;
    button.setAttribute('aria-label', `${node.kind} ${node.namespace || 'cluster'} / ${node.name}, ${node.status}`);
    if (map) { button.append(el('span', `${node.kind} · ${node.namespace || 'cluster'}`), el('strong', node.name), el('span', node.status, node.status === 'Ready' ? 'good' : ['Missing','Failed','Conflict'].includes(node.status) ? 'bad' : 'warn')); }
    else button.textContent = `${node.kind} · ${node.namespace || 'cluster'} / ${node.name} · ${node.status}`;
    button.addEventListener('click', () => select(node.id)); return button;
  }
  function render() {
    if (!graph) return;
    const search = $('topo-search').value.trim().toLowerCase(), kind = $('topo-kind').value, state = $('topo-state').value;
    const all = graph.nodes.filter(n => (!search || `${n.kind} ${n.namespace} ${n.name}`.toLowerCase().includes(search)) && (!kind || n.kind === kind) && (!state || (state === 'attention' ? ['NotReady','Unknown','Degraded','Missing','Failed','Stopped','Pending','Conflict'].includes(n.status) : n.status === state)));
    const visible = all.slice(0, 120); const visibleIds = new Set(visible.map(n => n.id));
    const focused = document.activeElement?.dataset.topoId;
    const stage = $('topo-stage'); stage.replaceChildren(); const list = $('topo-list'); list.replaceChildren();
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg'); svg.setAttribute('aria-hidden', 'true'); stage.append(svg);
    // Keep positions for surviving nodes; reuse gaps left by removed nodes.
    const currentIds = new Set(graph.nodes.map(n => n.id)); for (const id of positions.keys()) if (!currentIds.has(id)) positions.delete(id);
    for (const node of visible) if (!positions.has(node.id)) {
      const c = col(node.kind), used = new Set([...positions.values()].filter(p => p.c === c).map(p => p.row)); let row = 0; while (used.has(row)) row++; positions.set(node.id, {c, row});
    }
    const maxRow = Math.max(0, ...visible.map(n => positions.get(n.id).row)); const width = 1270, height = Math.max(390, (maxRow + 1) * 88 + 55);
    for (let i = 0; i < columns.length; i++) { const heading = el('span', columns[i], 'topo-column'); heading.style.left = `${i * 210 + 16}px`; stage.append(heading); }
    for (const edge of graph.edges) if (visibleIds.has(edge.from) && visibleIds.has(edge.to)) {
      const a = positions.get(edge.from), b = positions.get(edge.to); const x1 = a.c * 210 + 194, y1 = a.row * 88 + 76, x2 = b.c * 210 + 16, y2 = b.row * 88 + 76;
      const line = document.createElementNS('http://www.w3.org/2000/svg', 'path'); line.setAttribute('d', `M${x1},${y1} C${x1 + 35},${y1} ${x2 - 35},${y2} ${x2},${y2}`); line.dataset.from = edge.from; line.dataset.to = edge.to; svg.append(line);
    }
    svg.setAttribute('width', width); svg.setAttribute('height', height);
    for (const node of visible) {
      const pos = positions.get(node.id); const button = buttonFor(node, true); button.style.left = `${pos.c * 210 + 16}px`; button.style.top = `${pos.row * 88 + 40}px`; stage.append(button);
      const item = el('div', undefined, 'topo-list-item'); item.append(buttonFor(node, false));
      for (const edge of graph.edges.filter(e => e.from === node.id || e.to === node.id)) {
        const from = graph.nodes.find(n => n.id === edge.from), to = graph.nodes.find(n => n.id === edge.to);
        if (from && to) item.append(el('p', `${from.kind} ${from.name} → ${to.kind} ${to.name}: ${edge.relation} (${edge.evidence})`));
      }
      list.append(item);
    }
    stage.style.width = `${width}px`; stage.style.height = `${height}px`; stage.style.transform = `scale(${zoom})`;
    $('topo-canvas').style.width = `${width * zoom}px`; $('topo-canvas').style.height = `${height * zoom}px`;
    $('topo-viewport').hidden = listMode; list.hidden = !listMode; $('topo-view').setAttribute('aria-pressed', String(listMode)); $('topo-view').textContent = listMode ? 'Map view' : 'List view';
    $('topo-count').textContent = `${visible.length} shown / ${graph.nodes.length} loaded · ${graph.edges.length} relationships${all.length > 120 || graph.truncated ? ' · Limited: narrow your scope or filters' : ''}`;
    $('topo-message').textContent = !all.length ? (graph.nodes.length ? 'No resources match these filters. Clear the search or choose All kinds / All states.' : 'No resources in this permitted scope.') : baseMessage;
    detail(true); decorate();
    if (focused) [...document.querySelectorAll('[data-topo-id]')].find(b => b.dataset.topoId === focused && !b.closest('[hidden]'))?.focus({preventScroll: true});
  }
  function fitMap() {
    if (!graph) { message('Connect first to fit a loaded map.'); return; }
    listMode = false; render();
    zoom = Math.min(1, Math.max(.55, ($('topo-viewport').clientWidth - 4) / 1270));
    $('topo-viewport').scrollTo(0, 0); render();
  }
  async function refresh() {
    if (!active || busy) return;
    busy = true; const generation = epoch; const controller = new AbortController(); request = controller;
    const timeout = setTimeout(() => controller.abort(), 8000); $('topo-refresh').disabled = true;
    try {
      const response = await fetch(`/royak/v1/topology${namespace ? '?namespace=' + encodeURIComponent(namespace) : ''}`, {headers: headers(), credentials: 'omit', signal: controller.signal, cache: 'no-store'});
      if (generation !== epoch) return;
      if (!response.ok) { const e = new Error(response.status === 401 ? 'Authentication required. Enter a valid bearer token and reconnect.' : response.status === 403 ? 'Permission denied for this scope. Choose your permitted namespace or use a read-only token with pod-list permission.' : `Topology unavailable (HTTP ${response.status}). Retry when the API recovers.`); e.auth = response.status === 401 || response.status === 403; throw e; }
      const data = await response.json(); if (generation !== epoch) return;
      if (data.schema_version !== 1 || !Array.isArray(data.nodes) || !Array.isArray(data.edges)) throw new Error('Unsupported topology response; update the dashboard and server together.');
      const firstSnapshot = graph === null;
      graph = data; lastSuccess = Date.now(); $('status').textContent = data.warnings.some(w => w.startsWith('Not permitted') || w.includes('unavailable')) ? 'Partial view' : 'Connected';
      const oldKind = $('topo-kind').value, kinds = [...new Set(data.nodes.map(n => n.kind))].sort();
      if (oldKind && !kinds.includes(oldKind)) kinds.push(oldKind);
      $('topo-kind').replaceChildren(new Option('All kinds', ''), ...kinds.map(k => new Option(k, k))); $('topo-kind').value = oldKind;
      $('topo-time').textContent = `Observed ${new Date(data.observed_at_unix_ms).toLocaleTimeString()} · generation ${data.generation}`;
      $('topo-warning-list').replaceChildren(...data.warnings.map(w => el('li', w)));
      message(`${data.truncated ? 'Snapshot limited. ' : ''}Select a resource to follow its relationships. Refreshes every 5 seconds.`); render();
      if (firstSnapshot && !listMode) fitMap();
    } catch (e) {
      if (generation !== epoch) return;
      if (e.auth) { clearData(); $('topo-token').focus({preventScroll:true}); }
      $('status').textContent = e.auth ? 'Not authorized' : 'Stale / offline';
      message(e.auth ? e.message : `${e.name === 'AbortError' ? 'Topology request timed out.' : e.message} ${graph ? 'Previous snapshot retained, not live.' : 'No snapshot loaded.'} Use Refresh to retry.`);
    } finally { clearTimeout(timeout); if (generation === epoch) { busy = false; $('topo-refresh').disabled = false; } }
  }
  $('topo-auth').addEventListener('submit', event => {
    event.preventDefault(); request?.abort(); epoch++; busy = false;
    token = $('topo-token').value || token; $('topo-token').value = ''; namespace = $('topo-namespace').value.trim(); active = true;
    clearData(); $('topo-disconnect').hidden = false; $('status').textContent = 'Connecting'; message('Loading authorized resources…');
    sessionStatus();
    window.dispatchEvent(new Event('royak-session')); refresh();
  });
  $('topo-disconnect').addEventListener('click', () => { request?.abort(); epoch++; active = false; busy = false; token = ''; clearData(); $('status').textContent = 'Not connected'; $('topo-disconnect').hidden = true; sessionStatus(); message('Disconnected. Token cleared from memory.'); });
  for (const id of ['topo-token','topo-namespace']) $(id).addEventListener('input', sessionStatus);
  for (const id of ['topo-search','topo-kind','topo-state']) $(id).addEventListener(id === 'topo-search' ? 'input' : 'change', render);
  $('topo-refresh').addEventListener('click', () => { if (active) refresh(); else message('Connect first to load authorized resources.'); });
  $('topo-view').addEventListener('click', () => { listMode = !listMode; render(); });
  $('topo-zoom-in').addEventListener('click', () => { zoom = Math.min(1.6, zoom + .15); render(); });
  $('topo-zoom-out').addEventListener('click', () => { zoom = Math.max(.55, zoom - .15); render(); });
  $('topo-reset').addEventListener('click', () => { zoom = 1; selected = ''; positions.clear(); $('topo-search').value = ''; $('topo-kind').value = ''; $('topo-state').value = ''; $('topo-viewport').scrollTo(0, 0); render(); });
  $('topo-fit').addEventListener('click', fitMap);
  setInterval(() => { if (!document.hidden && active) refresh(); if (graph && lastSuccess && Date.now() - lastSuccess > 15000) $('status').textContent = 'Stale snapshot'; }, 5000);
})();
