import { FormEvent, useEffect, useMemo, useState } from 'react'
import { api } from './api'
import type { Baseline, Cycle, Dashboard } from './types'

type LldRow = {
  lldid: number; name: string; hostid: number; object_kind: string; prototype_id: number
  eligible_children: number; existing_children: number; discovered_children: number
  lost_children: number; scheduled_delete: number; scheduled_disable: number; result: string
  baseline_lifetime?: string; current_lifetime?: string; lifetime_type?: number; enabled_lifetime?: string
}
type ProxyRow = {
  proxyid: number; baseline_name: string; current_name?: string; version?: string
  compatibility?: number; state?: number; name_changed: boolean; name_change_expected: boolean
  hosts: number; items_total: number; items_ok: number
}
type ActionRow = {
  actionid: number; name: string; baseline_status: number; current_status?: number
  status_change_expected: boolean
  baseline_runs: Array<{rank:number; eventid:number; summary_status:string; clock:number}>
  current_runs: Array<{rank:number; eventid:number; summary_status:string; clock:number}>
}
type MediaRow = {
  mediatypeid: number; name: string; type: number; baseline_status: number
  current_status?: number; status_change_expected: boolean
}

const fmt = new Intl.NumberFormat('pt-BR')
const dateFmt = new Intl.DateTimeFormat('pt-BR', { dateStyle: 'short', timeStyle: 'medium' })

function Card({ title, value, detail, tone='neutral' }: {title:string; value:string|number; detail?:string; tone?:string}) {
  return <div className={`card tone-${tone}`}><div className="card-title">{title}</div><div className="card-value">{value}</div>{detail && <div className="card-detail">{detail}</div>}</div>
}

function Progress({ current, total }: {current:number; total:number}) {
  const pct = total ? Math.min(100, current * 100 / total) : 0
  return <div className="progress-wrap"><div className="progress"><span style={{width:`${pct}%`}} /></div><b>{pct.toFixed(1)}%</b></div>
}

function HistoryChart({ rows }: {rows: Cycle[]}) {
  const points = useMemo(() => {
    const data = [...rows].reverse().filter(r => r.status === 'COMPLETE' && r.metrics?.items_percent != null)
    if (!data.length) return ''
    const w=720, h=150, pad=15
    return data.map((r, idx) => {
      const x = data.length === 1 ? w/2 : pad + idx*(w-2*pad)/(data.length-1)
      const y = h-pad-(Number(r.metrics.items_percent)/100)*(h-2*pad)
      return `${x},${y}`
    }).join(' ')
  }, [rows])
  return <div className="chart"><svg viewBox="0 0 720 150" preserveAspectRatio="none"><line x1="0" y1="135" x2="720" y2="135" className="axis"/><polyline points={points} className="line" /></svg><div className="chart-caption">Evolução de itens com coleta pós-upgrade confirmada</div></div>
}

function Runs({ rows }: {rows: ActionRow['current_runs']}) {
  if (!rows?.length) return <span className="muted">sem execução</span>
  return <div className="runs">{rows.map(r => <span key={r.rank} className={`pill ${r.summary_status.toLowerCase()}`}>#{r.rank} {r.summary_status}</span>)}</div>
}

export default function App() {
  const [dashboard, setDashboard] = useState<Dashboard | null>(null)
  const [baselines, setBaselines] = useState<Baseline[]>([])
  const [history, setHistory] = useState<Cycle[]>([])
  const [lld, setLld] = useState<LldRow[]>([])
  const [proxies, setProxies] = useState<ProxyRow[]>([])
  const [actions, setActions] = useState<ActionRow[]>([])
  const [media, setMedia] = useState<MediaRow[]>([])
  const [name, setName] = useState('Upgrade Zabbix 6 → 7')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [tab, setTab] = useState<'overview'|'lld'|'proxies'|'actions'>('overview')
  const [appConfig, setAppConfig] = useState<{old_url_configured:boolean; new_url_configured:boolean} | null>(null)

  async function refresh() {
    try {
      const [d,b,h,l,p,a,m,cfg] = await Promise.all([
        api<Dashboard>('/api/dashboard'), api<Baseline[]>('/api/baselines'),
        api<Cycle[]>('/api/cycles/history?limit=40'), api<LldRow[]>('/api/lld/regressions?limit=300'),
        api<ProxyRow[]>('/api/proxies'), api<ActionRow[]>('/api/actions'), api<MediaRow[]>('/api/media-types'),
        api<{old_url_configured:boolean; new_url_configured:boolean}>('/api/config')
      ])
      setDashboard(d); setBaselines(b); setHistory(h); setLld(l); setProxies(p); setActions(a); setMedia(m); setAppConfig(cfg); setError('')
    } catch (e) { setError(e instanceof Error ? e.message : String(e)) }
  }

  useEffect(() => { refresh(); const t=setInterval(refresh, 5000); return () => clearInterval(t) }, [])

  async function createBaseline(e:FormEvent) {
    e.preventDefault(); setBusy(true)
    try { await api('/api/baselines',{method:'POST',body:JSON.stringify({name})}); await refresh() }
    catch(e){setError(e instanceof Error?e.message:String(e))} finally {setBusy(false)}
  }
  async function freeze(id:string) {
    setBusy(true); try { await api(`/api/baselines/${id}/freeze`,{method:'POST'}); await refresh() }
    catch(e){setError(e instanceof Error?e.message:String(e))} finally {setBusy(false)}
  }
  async function runCycle(){setBusy(true);try{await api('/api/cycles/run',{method:'POST'});await refresh()}catch(e){setError(e instanceof Error?e.message:String(e))}finally{setBusy(false)}}
  async function expected(object_type:string, object_id:number, field:string, enabled:boolean, note:string) {
    await api('/api/expected-changes',{method:'POST',body:JSON.stringify({object_type,object_id,field,enabled,note})}); await refresh()
  }

  const m = dashboard?.last_cycle?.metrics || {}
  const running = dashboard?.running_cycle
  return <div className="app">
    <header><div><h1>Zabbix Upgrade Validator</h1><p>Baseline Zabbix 6 × validação contínua Zabbix 7</p></div><button onClick={runCycle} disabled={busy || !dashboard?.baseline || !appConfig?.new_url_configured}>Executar coleta agora</button></header>
    {error && <div className="error">{error}</div>}
    {dashboard?.baseline && !appConfig?.new_url_configured && <div className="panel"><b>⏳ Aguardando ambiente Zabbix 7</b><p className="muted">A baseline pode permanecer congelada. Nenhum ciclo pós-upgrade será iniciado até NEW_ZABBIX_URL e NEW_ZABBIX_TOKEN serem configurados.</p></div>}

    {!dashboard?.baseline && <section className="setup panel"><h2>Fotografia pré-upgrade</h2><form onSubmit={createBaseline}><input value={name} onChange={e=>setName(e.target.value)} /><button disabled={busy}>Criar fotografia</button></form><p>A fotografia coleta somente hosts ativos e marca como elegíveis os objetos saudáveis. Depois de concluída, congele a baseline antes do cutover.</p></section>}

    <section className="baseline-strip panel">
      <div><span>Baseline ativa</span><b>{dashboard?.baseline?.name || 'Nenhuma congelada'}</b></div>
      <div><span>Versão origem</span><b>{dashboard?.baseline?.source_version || '—'}</b></div>
      <div><span>Último ciclo completo</span><b>{dashboard?.last_cycle?.finished_at ? dateFmt.format(new Date(dashboard.last_cycle.finished_at)) : '—'}</b></div>
      <div><span>Itens baseline</span><b>{fmt.format(dashboard?.baseline?.totals?.items || 0)}</b></div>
    </section>

    {running && <section className="panel running"><div><h3>Coleta em andamento</h3><small>{running.hosts_processed} / {running.hosts_total} hosts processados</small></div><Progress current={running.hosts_processed} total={running.hosts_total}/></section>}

    <nav>{(['overview','lld','proxies','actions'] as const).map(t=><button className={tab===t?'active':''} key={t} onClick={()=>setTab(t)}>{t==='overview'?'Visão geral':t==='lld'?'LLD':t==='proxies'?'Proxies':'Actions / Media'}</button>)}</nav>

    {tab==='overview' && <>
      <section className="grid cards">
        <Card title="Hosts" value={`${fmt.format(m.hosts_ok||0)} / ${fmt.format(m.hosts_total||0)}`} tone={(m.hosts_regression||0)>0?'bad':'good'} />
        <Card title="Interfaces" value={`${fmt.format(m.interfaces_ok||0)} / ${fmt.format(m.interfaces_total||0)}`} detail={`${fmt.format(m.interfaces_regression||0)} regressões`} tone={(m.interfaces_regression||0)>0?'warn':'good'} />
        <Card title="Itens validados" value={`${m.items_percent ?? 0}%`} detail={`${fmt.format(m.items_ok||0)} / ${fmt.format(m.items_total||0)}`} tone={(m.items_unsupported||0)+(m.items_missing||0)>0?'warn':'good'} />
        <Card title="Itens pending" value={fmt.format(m.items_pending||0)} detail="ainda sem lastclock pós-baseline" />
        <Card title="Unsupported novos" value={fmt.format(m.items_unsupported||0)} tone={(m.items_unsupported||0)>0?'bad':'good'} />
        <Card title="Itens LLD lost" value={fmt.format(m.items_lld_lost||0)} detail={`${fmt.format(m.lld_scheduled_delete||0)} com delete agendado`} tone={(m.items_lld_lost||0)>0?'bad':'good'} />
        <Card title="LLD mass loss" value={fmt.format(m.lld_mass_loss||0)} detail="prototype com baseline >0 e atual=0" tone={(m.lld_mass_loss||0)>0?'bad':'good'} />
        <Card title="LLD retenção perigosa" value={fmt.format(m.lld_retention_regression||0)} detail="antes >0, agora remoção imediata/0" tone={(m.lld_retention_regression||0)>0?'bad':'good'} />
        <Card title="Network discoveries" value={`${fmt.format(m.network_discoveries_ok||0)} / ${fmt.format(m.network_discoveries_total||0)}`} tone={(m.network_discoveries_regression||0)>0?'warn':'good'} />
        <Card title="Triggers" value={`${fmt.format(m.triggers_ok||0)} / ${fmt.format(m.triggers_total||0)}`} detail={`${fmt.format(m.trigger_value_changed||0)} mudaram OK/PROBLEM`} tone={(m.triggers_regression||0)>0?'warn':'good'} />
      </section>
      <section className="panel"><h2>Evolução</h2><HistoryChart rows={history}/></section>
      <section className="panel"><h2>Regressões / alertas</h2>{dashboard?.alerts?.length ? <div className="alerts">{dashboard.alerts.map(a=><div className={`alert sev-${a.severity.toLowerCase()}`} key={a.id}><b>{a.severity}</b><span>{a.code}</span><p>{a.message}</p></div>)}</div>:<p className="muted">Nenhuma regressão registrada no último ciclo.</p>}</section>
      <section className="panel"><h2>Baselines</h2><table><thead><tr><th>Nome</th><th>Status</th><th>Versão</th><th>Itens saudáveis</th><th>Ação</th></tr></thead><tbody>{baselines.map(b=><tr key={b.id}><td>{b.name}</td><td><span className={`pill ${b.status.toLowerCase()}`}>{b.status}</span></td><td>{b.source_version||'—'}</td><td>{fmt.format(b.totals?.items||0)}</td><td>{b.status==='READY'&&<button onClick={()=>freeze(b.id)} disabled={busy}>🔒 Congelar</button>}</td></tr>)}</tbody></table></section>
    </>}

    {tab==='lld' && <section className="panel"><h2>LLD: perda de filhos</h2><p>Mostra somente LLD/prototypes que tinham filhos saudáveis no baseline e perderam quantidade no Zabbix 7.</p><table><thead><tr><th>LLD</th><th>Host ID</th><th>Tipo</th><th>Prototype</th><th>Baseline</th><th>Descobertos</th><th>Lost</th><th>Delete</th><th>Disable</th><th>Retenção 6→7</th><th>Status</th></tr></thead><tbody>{lld.map((r,idx)=><tr key={`${r.lldid}-${r.object_kind}-${r.prototype_id}-${idx}`}><td>{r.name}<small>ID {r.lldid}</small></td><td>{r.hostid}</td><td>{r.object_kind}</td><td>{r.prototype_id}</td><td>{fmt.format(r.eligible_children)}</td><td>{fmt.format(r.discovered_children)}</td><td>{fmt.format(r.lost_children)}</td><td>{fmt.format(r.scheduled_delete)}</td><td>{fmt.format(r.scheduled_disable)}</td><td>{r.baseline_lifetime||'—'} → {r.current_lifetime||'—'}</td><td><span className={`pill ${r.result.toLowerCase()}`}>{r.result}</span></td></tr>)}</tbody></table>{!lld.length&&<p className="muted">Nenhuma perda LLD detectada.</p>}</section>}

    {tab==='proxies' && <section className="panel"><h2>Proxies por ID</h2><table><thead><tr><th>ID</th><th>Baseline</th><th>Atual</th><th>Versão</th><th>Hosts</th><th>Itens coletando</th><th>Nome</th></tr></thead><tbody>{proxies.map(p=><tr key={p.proxyid}><td>{p.proxyid}</td><td>{p.baseline_name}</td><td>{p.current_name||'AUSENTE'}</td><td>{p.version||'—'}</td><td>{fmt.format(p.hosts)}</td><td>{fmt.format(p.items_ok)} / {fmt.format(p.items_total)}</td><td>{p.name_changed ? <button className={p.name_change_expected?'expected':''} onClick={()=>expected('proxy',p.proxyid,'name',!p.name_change_expected,'Renomeação temporária para isolar comunicação durante cutover')}>{p.name_change_expected?'🔵 Esperado':'Marcar esperado'}</button>:<span className="pill good">igual</span>}</td></tr>)}</tbody></table></section>}

    {tab==='actions' && <div className="stack"><section className="panel"><h2>Actions</h2><table><thead><tr><th>ID</th><th>Action</th><th>Antes</th><th>Agora</th><th>Últimas execuções atuais</th><th>Cutover</th></tr></thead><tbody>{actions.map(a=><tr key={a.actionid}><td>{a.actionid}</td><td>{a.name}</td><td>{a.baseline_status===0?'Enabled':'Disabled'}</td><td>{a.current_status===0?'Enabled':a.current_status==null?'Ausente':'Disabled'}</td><td><Runs rows={a.current_runs}/></td><td>{a.current_status!==0&&<button className={a.status_change_expected?'expected':''} onClick={()=>expected('action',a.actionid,'status',!a.status_change_expected,'Action desabilitada intencionalmente para evitar duplicidade durante cutover')}>{a.status_change_expected?'🔵 Inibida intencionalmente':'Marcar inibição esperada'}</button>}</td></tr>)}</tbody></table></section><section className="panel"><h2>Media Types</h2><table><thead><tr><th>ID</th><th>Media Type</th><th>Antes</th><th>Agora</th><th>Cutover</th></tr></thead><tbody>{media.map(mr=><tr key={mr.mediatypeid}><td>{mr.mediatypeid}</td><td>{mr.name}</td><td>{mr.baseline_status===0?'Enabled':'Disabled'}</td><td>{mr.current_status===0?'Enabled':mr.current_status==null?'Ausente':'Disabled'}</td><td>{mr.current_status!==0&&<button className={mr.status_change_expected?'expected':''} onClick={()=>expected('media_type',mr.mediatypeid,'status',!mr.status_change_expected,'Media Type desabilitada intencionalmente para evitar duplicidade durante cutover')}>{mr.status_change_expected?'🔵 Inibida intencionalmente':'Marcar inibição esperada'}</button>}</td></tr>)}</tbody></table></section></div>}
  </div>
}
