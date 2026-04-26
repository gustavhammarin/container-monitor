import { useState, useEffect, useRef } from 'react'
import './App.css'

// ── types ────────────────────────────────────────────────────────────────────

interface Status {
  lastPoll: string | null
  isFinished: boolean
}

interface NetworkEntry {
  timestamp: string
  source: string
  domain: string
  query_type?: string
  method?: string
  path?: string
  status_code?: string
  type: string
}

interface TrivyVuln {
  VulnerabilityID: string
  PkgName: string
  Severity: string
  Title: string
}

interface TrivyResult {
  ArtifactName: string
  Metadata: { OS: { Family: string; Name: string } }
  Results: Array<{
    Target: string
    Vulnerabilities: TrivyVuln[] | null
  }>
}

interface Analysis {
  verdict: 'safe' | 'suspicious' | 'dangerous'
  summary: string
  critical: string[]
  warnings: string[]
  network_flags: string[]
}

type Phase = 'config' | 'polling' | 'fetching' | 'analyzing' | 'done' | 'error'

// ── LLM ─────────────────────────────────────────────────────────────────────

const SYSTEM_PROMPT = `You are a container security analyst. Analyze the provided scan data and return ONLY a valid JSON object. No markdown fences, no explanation.

Output this exact structure:
{
  "verdict": "safe" | "suspicious" | "dangerous",
  "summary": "one sentence overall assessment",
  "critical": ["finding"],
  "warnings": ["finding"],
  "network_flags": ["domain or behavior"]
}

Rules:
- verdict: dangerous=any CRITICAL CVE or confirmed malicious event, suspicious=HIGH CVEs or unusual activity, safe=nothing notable
- critical: every CRITICAL CVE (format: "pkgname CVE-ID: short title"), every confirmed malicious Falco alert
- warnings: every HIGH and MEDIUM CVE (same format), every Falco warning-level event
- network_flags: list every domain from network_domains — just the domain name, no filtering. If empty, return []
- Max 20 words per finding
- Include ALL CVEs provided, do not summarize or group them`

async function analyze(
  apiKey: string,
  trivy: TrivyResult[],
  network: NetworkEntry[],
  falco: Record<string, unknown>[]
): Promise<Analysis> {
  const vulns = trivy.flatMap(r =>
    (r.Results ?? []).flatMap(res =>
      (res.Vulnerabilities ?? [])
        .filter(v => v.Severity === 'CRITICAL' || v.Severity === 'HIGH' || v.Severity === 'MEDIUM')
        .map(v => `${v.PkgName} ${v.VulnerabilityID} (${v.Severity}): ${v.Title}`)
    )
  )

  const domains = [...new Set(network.map(e => e.domain).filter(Boolean))].slice(0, 60)
  const falcoEvents = falco.slice(0, 40)
  const images = trivy.map(r => r.ArtifactName)

  console.log('[analyze] images:', images)
  console.log('[analyze] vulns:', vulns.length, 'domains:', domains.length, 'falco:', falcoEvents.length)
  console.log('[analyze] sample vulns:', vulns.slice(0, 3))

  const userContent = JSON.stringify({
    images,
    trivy_vulns: vulns.slice(0, 100),
    network_domains: domains,
    falco_events: falcoEvents,
  })

  const res = await fetch(
    'https://generativelanguage.googleapis.com/v1beta/openai/chat/completions',
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: 'gemini-2.5-flash',
        messages: [
          { role: 'system', content: SYSTEM_PROMPT },
          { role: 'user', content: userContent },
        ],
        temperature: 0.1,
      }),
    }
  )

  if (!res.ok) {
    const err = await res.text()
    throw new Error(`Gemini ${res.status}: ${err}`)
  }

  const data = await res.json()
  const raw: string = data.choices[0].message.content.trim()
  const text = raw.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '')
  return JSON.parse(text) as Analysis
}

// ── components ───────────────────────────────────────────────────────────────

function Spinner() {
  return <div className="spinner" />
}

function VerdictBadge({ verdict }: { verdict: Analysis['verdict'] }) {
  return <span className={`verdict verdict--${verdict}`}>{verdict.toUpperCase()}</span>
}

function FindingList({ items, color }: { items: string[]; color: string }) {
  if (!items?.length) return <p className="empty">None detected</p>
  return (
    <ul className="findings">
      {items.map((item, i) => (
        <li key={i} style={{ borderLeftColor: color }}>{item}</li>
      ))}
    </ul>
  )
}

// ── app ───────────────────────────────────────────────────────────────────────

export default function App() {
  const [host, setHost] = useState('192.168.64.3:8081')
  const [apiKey, setApiKey] = useState('')
  const [phase, setPhase] = useState<Phase>('config')
  const [status, setStatus] = useState<Status | null>(null)
  const [analysis, setAnalysis] = useState<Analysis | null>(null)
  const [dataStats, setDataStats] = useState<{ trivy: number; network: number; falco: number } | null>(null)
  const [error, setError] = useState('')
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  function stopPoll() {
    if (pollRef.current) clearInterval(pollRef.current)
  }

  async function fetchAndAnalyze() {
    setPhase('fetching')
    try {
      const base = `http://${host}`
      const [trivyRes, networkRes, falcoRes] = await Promise.all([
        fetch(`${base}/logs/trivy`),
        fetch(`${base}/logs/network`),
        fetch(`${base}/logs/falco`),
      ])
      const trivy: TrivyResult[] = await trivyRes.json()
      const network: NetworkEntry[] = await networkRes.json()
      const falco: Record<string, unknown>[] = await falcoRes.json()

      const trivyArr = trivy ?? []
      const networkArr = network ?? []
      const falcoArr = falco ?? []
      setDataStats({ trivy: trivyArr.length, network: networkArr.length, falco: falcoArr.length })

      setPhase('analyzing')
      const result = await analyze(apiKey, trivyArr, networkArr, falcoArr)
      setAnalysis(result)
      setPhase('done')
    } catch (e) {
      setError(String(e))
      setPhase('error')
    }
  }

  function startScan() {
    if (!host || !apiKey) return
    setPhase('polling')
    setError('')
    setAnalysis(null)

    const base = `http://${host}`
    pollRef.current = setInterval(async () => {
      try {
        const res = await fetch(`${base}/status`)
        const s: Status = await res.json()
        setStatus(s)
        if (s.isFinished) {
          stopPoll()
          fetchAndAnalyze()
        }
      } catch (e) {
        stopPoll()
        setError(`Cannot reach ${host}: ${e}`)
        setPhase('error')
      }
    }, 3000)
  }

  useEffect(() => stopPoll, [])

  // ── render ─────────────────────────────────────────────────────────────────

  if (phase === 'config') {
    return (
      <div className="page">
        <div className="card config-card">
          <h1>Container Monitor</h1>
          <p className="subtitle">Security scan analysis</p>
          <div className="form">
            <label>
              <span>VM address</span>
              <input
                value={host}
                onChange={e => setHost(e.target.value)}
                placeholder="192.168.64.2:8081"
                spellCheck={false}
              />
            </label>
            <label>
              <span>Gemini API key</span>
              <input
                type="password"
                value={apiKey}
                onChange={e => setApiKey(e.target.value)}
                placeholder="AIza..."
                spellCheck={false}
              />
            </label>
            <button
              className="btn-primary"
              onClick={startScan}
              disabled={!host || !apiKey}
            >
              Start analysis
            </button>
          </div>
        </div>
      </div>
    )
  }

  if (phase === 'polling') {
    return (
      <div className="page">
        <div className="card status-card">
          <Spinner />
          <h2>Scan in progress</h2>
          <p>Waiting for VM to finish scanning…</p>
          {status && (
            <p className="meta">
              Status: {status.isFinished ? 'finished' : 'running'}
            </p>
          )}
        </div>
      </div>
    )
  }

  if (phase === 'fetching') {
    return (
      <div className="page">
        <div className="card status-card">
          <Spinner />
          <h2>Fetching logs</h2>
          <p>Pulling security data from VM…</p>
        </div>
      </div>
    )
  }

  if (phase === 'analyzing') {
    return (
      <div className="page">
        <div className="card status-card">
          <Spinner />
          <h2>Analyzing</h2>
          <p>LLM reading logs…</p>
          {dataStats && (
            <p className="meta">
              trivy: {dataStats.trivy} · network: {dataStats.network} · falco: {dataStats.falco}
            </p>
          )}
        </div>
      </div>
    )
  }

  if (phase === 'error') {
    return (
      <div className="page">
        <div className="card status-card">
          <h2 className="error-title">Error</h2>
          <p className="error-msg">{error}</p>
          <button className="btn-primary" onClick={() => setPhase('config')}>
            Back
          </button>
        </div>
      </div>
    )
  }

  if (phase === 'done' && analysis) {
    return (
      <div className="page">
        <div className="results">
          <div className="results-header">
            <h1>Scan Results</h1>
            <VerdictBadge verdict={analysis.verdict} />
          </div>
          <p className="summary">{analysis.summary}</p>

          <div className="grid">
            <div className="card">
              <h3>Critical findings</h3>
              <FindingList items={analysis.critical} color="var(--red)" />
            </div>
            <div className="card">
              <h3>Warnings</h3>
              <FindingList items={analysis.warnings} color="var(--orange)" />
            </div>
            <div className="card">
              <h3>Network flags</h3>
              <FindingList items={analysis.network_flags} color="var(--blue)" />
            </div>
          </div>

          <button className="btn-secondary" onClick={() => setPhase('config')}>
            New scan
          </button>
        </div>
      </div>
    )
  }

  return null
}
