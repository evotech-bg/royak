"""Conservative bounded leak/trend checks, not proof of absence of all leaks."""
import statistics
import math

MIB = 1024 ** 2


def guest_cleanup_passed(value):
    return (value.get('service_active')=='inactive' and value.get('service_enabled')=='disabled' and
            value.get('royak_process_alive') is False and value.get('containers')==[] and
            value.get('all_container_count')==0 and
            value.get('wireguard_present') is False and value.get('owned_firewall_rules')==0)


def resource_report(samples, minimum_span=300, audit_first_use=None):
    groups = {}
    container_groups, path_groups = {}, {}
    # A successful grant durably writes the issuer's audit before returning.
    # Followers that have never issued a grant legitimately have no file.
    audit_first_use={n:0 for n in (1,2,3)} if audit_first_use is None else audit_first_use
    audit_seen=set();audit_absences=[]
    errors = []
    for row in samples:
        if row.get("error"):
            continue  # unavailable is not zero; fault coverage is checked separately
        metric, node = row["metrics"], row["node"]
        if metric.get('schema_version')!=2:
            errors.append(dict(node=node,reason='missing PID/Raft telemetry contract v2'))
        for path in ('/lab/state.json.raft','/lab/royak.log','/lab/data/connect-audit.jsonl'):
            usage=metric.get('paths',{}).get(path,{})
            if usage.get('present') is not True or not isinstance(usage.get('bytes'),int):
                if path.endswith('connect-audit.jsonl') and node not in audit_seen and (
                        node not in audit_first_use or row.get('sample_started_s',row['elapsed_s'])<audit_first_use[node]):
                    audit_absences.append(dict(node=node,elapsed_s=row['elapsed_s'],reason='not created before first acknowledged grant',bytes=None))
                    continue
                errors.append(dict(node=node,reason='required path telemetry unavailable',path=path))
                continue
            if path.endswith('connect-audit.jsonl'):audit_seen.add(node)
            if path.endswith('.raft') and usage.get('kind')!='directory':
                errors.append(dict(node=node,reason='Raft telemetry is not a directory',path=path))
            path_groups.setdefault((node,metric['boot_id'],path),[]).append((row['elapsed_s'],usage['bytes']))
        for c in metric['containers']:
            if c['oom']:errors.append(dict(node=node,reason='container OOM'))
            if not c.get('running'):continue
            if c.get('init') is not True:
                errors.append(dict(node=node,reason='soak probe container lacks PID-1 reaper',container=c.get('id')))
            census=c.get('census')
            if not census or c.get('census_error'):
                errors.append(dict(node=node,reason='container process census unavailable',container=c.get('id')))
                continue
            key=(node,metric['boot_id'],c['id'],c['started_at'])
            container_groups.setdefault(key,[]).append((row['elapsed_s'],row.get('phase'),census))
        if metric['root_free_bytes'] < 2 * 1024 ** 3:
            errors.append(dict(node=node,reason='guest disk reserve below 2 GiB'))
        if not metric.get('process'):continue
        p = metric["process"]
        key = (node, metric["boot_id"], p["pid"], p["start_ticks"])
        groups.setdefault(key, []).append((row["elapsed_s"], p))
        if p["rss_bytes"] > 256 * MIB:
            errors.append(dict(node=node, reason="Royak RSS exceeds declared 256 MiB ceiling"))
    trends = []
    for key, values in groups.items():
        values.sort(key=lambda v:v[0])
        if len(values) < 8 or values[-1][0] - values[0][0] < minimum_span:
            continue
        n = max(2, len(values) // 4)
        deltas = {name: statistics.median(v[1][name] for v in values[-n:]) -
                        statistics.median(v[1][name] for v in values[:n])
                  for name in ("rss_bytes", "fds", "threads")}
        ok = deltas["rss_bytes"] <= 64 * MIB and deltas["fds"] <= 32 and deltas["threads"] <= 8
        cpu=[]
        for (t0,p0),(t1,p1) in zip(values,values[1:]):
            if t1>t0 and 'cpu_ticks' in p0 and 'cpu_ticks' in p1:
                # Linux USER_HZ supplied by the guest, one full core = 100%.
                hz=next(r['metrics'].get('clock_ticks') for r in samples if r.get('node')==key[0] and r.get('metrics',{}).get('boot_id')==key[1])
                if hz:cpu.append(max(0,p1['cpu_ticks']-p0['cpu_ticks'])/hz/(t1-t0)*100)
        trends.append(dict(node=key[0], incarnation=list(key[1:]), samples=len(values),
                           span_s=values[-1][0] - values[0][0], median_deltas=deltas, passed=ok))
        trends[-1]['first']={name:values[0][1][name] for name in ('rss_bytes','fds','threads')}
        trends[-1]['last']={name:values[-1][1][name] for name in ('rss_bytes','fds','threads')}
        trends[-1]['peaks']={name:max(v[1][name] for v in values) for name in ('rss_bytes','fds','threads')}
        trends[-1]['cpu_one_core_percent']=dict(samples=len(cpu),mean=statistics.mean(cpu) if cpu else None,peak=max(cpu) if cpu else None)
        if not ok:
            errors.append(dict(node=key[0], reason="same-incarnation resource growth exceeds declared bound"))
    container_trends=[]
    for key,values in container_groups.items():
        values.sort(key=lambda v:v[0])
        zombies={}
        for t,phase,c in values:
            for p in c['zombies']:
                zombies.setdefault((p['pid'],p['start_ticks']),[]).append(t)
            if phase=='drain' and c['zombies']:
                errors.append(dict(node=key[0],reason='zombie remains after traffic drain',container=key[2],count=len(c['zombies'])))
        persistent=[dict(pid=p[0],start_ticks=p[1],observations=len(ts),span_s=max(ts)-min(ts))
                    for p,ts in zombies.items() if len(ts)>1 and max(ts)-min(ts)>=1]
        if persistent:errors.append(dict(node=key[0],reason='persistent container zombies',container=key[2],processes=persistent))
        peak=max(v[2]['tasks'] for v in values)
        if peak>64:errors.append(dict(node=key[0],reason='container task peak exceeds 64',container=key[2],peak=peak))
        if len(values)<8 or values[-1][0]-values[0][0]<minimum_span:continue
        n=max(2,len(values)//4)
        delta=statistics.median(v[2]['tasks'] for v in values[-n:])-statistics.median(v[2]['tasks'] for v in values[:n])
        ok=delta<=8 and peak<=64 and not persistent
        container_trends.append(dict(node=key[0],incarnation=list(key[1:]),samples=len(values),span_s=values[-1][0]-values[0][0],
            first_tasks=values[0][2]['tasks'],last_tasks=values[-1][2]['tasks'],peak_tasks=peak,median_task_gain=delta,
            peak_zombies=max(len(v[2]['zombies']) for v in values),persistent_zombies=persistent,passed=ok))
        if not ok:errors.append(dict(node=key[0],reason='same-container task growth exceeds declared bound',container=key[2]))
    paths=[]
    for key,values in path_groups.items():
        values.sort()
        n=max(1,len(values)//4)
        delta=statistics.median(v[1] for v in values[-n:])-statistics.median(v[1] for v in values[:n])
        peak=max(v[1] for v in values)
        gain_limit=16*MIB if key[2].endswith('.raft') else 32*MIB
        ok=peak<=64*MIB and delta<=gain_limit
        paths.append(dict(node=key[0],boot_id=key[1],path=key[2],samples=len(values),first_bytes=values[0][1],last_bytes=values[-1][1],
                          peak_bytes=peak,median_gain_bytes=delta,passed=ok))
        if not ok:errors.append(dict(node=key[0],reason='state/audit/log size exceeds declared bound',path=key[2]))
    return dict(schema_version=2,passed=not errors and {t['node'] for t in trends}=={1,2,3} and {t['node'] for t in container_trends}=={1,2,3},
                errors=errors,trends=trends,container_trends=container_trends,paths=paths,
                audit_first_use_s=audit_first_use,audit_required_nodes=sorted(audit_first_use),audit_absences=audit_absences,
                thresholds=dict(rss_peak_bytes=256 * MIB, rss_median_gain_bytes=64 * MIB,
                                fd_median_gain=32, thread_median_gain=8, minimum_span_s=minimum_span,
                                container_task_peak=64,container_task_median_gain=8,persistent_zombies=0,drain_zombies=0,
                                path_peak_bytes=64*MIB,raft_median_gain_bytes=16*MIB,audit_log_median_gain_bytes=32*MIB),
                missing_samples=sum(bool(r.get("error")) for r in samples),
                scope="bounded growth in observed process incarnations; restarts never merge or reset a trend")


def traffic_gate(events, rate, workers, minimum_window=20):
    groups = {}
    for e in events:
        if e.get("kind") == "app_complete":
            groups.setdefault(e["phase"], []).append(e)
    phases = {}
    for phase in ("baseline", "soak"):
        rows = groups.get(phase, [])
        span = max((e["elapsed_s"] for e in rows), default=0) - min((e["elapsed_s"] for e in rows), default=0)
        success = sum(e["status"] == 200 for e in rows)
        phases[phase] = dict(requests=len(rows), successes=success, span_s=span,
                             passed=bool(rows) and span >= minimum_window and success / len(rows) >= .99
                             and success >= .5 * rate * workers * span)
    return dict(passed=all(p["passed"] for p in phases.values()), phases=phases,
                scope="99 percent healthy-window responses plus at least half the declared offered rate; outages remain visible")


def continuity(events, faults, start, end, rate, window=60, recovery=20):
    """A quiet middle hour cannot be hidden by good first/last windows."""
    intervals, active = [], {}
    for event in faults:
        if event.get("kind")=="fault_start": active[event["fault"]]=event["elapsed_s"]
        elif event.get("kind")=="fault_end" and event["fault"] in active:
            intervals.append((active.pop(event["fault"]),event["elapsed_s"]+recovery))
    if active:
        return dict(passed=False, failure="unclosed fault window", windows=[])
    rows=[e for e in events if e.get("kind")=="app_complete"]
    windows=[]
    for t in range(math.ceil(start/window)*window,math.floor(end/window)*window,window):
        if any(a<t+window and b>t for a,b in intervals): continue
        selected=[e for e in rows if t<=e["elapsed_s"]<t+window]
        success=sum(e["status"]==200 for e in selected)
        ok=bool(selected) and success/len(selected)>=.99 and success>=rate*window*.5
        windows.append(dict(start=t,end=t+window,requests=len(selected),successes=success,passed=ok))
    return dict(passed=bool(windows) and all(w["passed"] for w in windows), windows=windows,
                scope="complete healthy minute windows; every fault and its declared recovery interval is separately retained")
