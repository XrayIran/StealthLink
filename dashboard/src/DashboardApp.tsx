import { useEffect, useState } from 'react'

type JsonMap = Record<string, unknown>

async function fetchJson(path: string): Promise<JsonMap> {
  const r = await fetch(path)
  if (!r.ok) throw new Error(`${path}: ${r.status}`)
  return r.json()
}

export function DashboardApp() {
  const [status, setStatus] = useState<JsonMap>({})
  const [metrics, setMetrics] = useState<JsonMap>({})
  const [tunnels, setTunnels] = useState<JsonMap>({})
  const [config, setConfig] = useState<JsonMap>({})
  const [err, setErr] = useState<string>('')

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const [s, m, t, c] = await Promise.all([
          fetchJson('/api/v1/status'),
          fetchJson('/api/v1/metrics'),
          fetchJson('/api/v1/tunnels'),
          fetchJson('/api/v1/config')
        ])
        if (!cancelled) {
          setStatus(s)
          setMetrics(m)
          setTunnels(t)
          setConfig(c)
          setErr('')
        }
      } catch (e) {
        if (!cancelled) setErr(String(e))
      }
    }
    load()
    const id = setInterval(load, 2000)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [])

  return (
    <main className="layout">
      <h1>StealthLink Dashboard</h1>
      {err && <p className="err">{err}</p>}
      <section>
        <h2>Status</h2>
        <pre>{JSON.stringify(status, null, 2)}</pre>
      </section>
      <section>
        <h2>Tunnels</h2>
        <pre>{JSON.stringify(tunnels, null, 2)}</pre>
      </section>
      <section>
        <h2>Metrics</h2>
        <pre>{JSON.stringify(metrics, null, 2)}</pre>
      </section>
      <section>
        <h2>Config</h2>
        <pre>{JSON.stringify(config, null, 2)}</pre>
      </section>
    </main>
  )
}
