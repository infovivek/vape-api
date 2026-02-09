import React, { useState } from 'react'

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000'

const initialTarget = {
  name: '',
  base_url: '',
  allowlisted_hosts: '',
  auth_header: '',
  api_key: '',
  authorization_text: ''
}

export default function App() {
  const [token, setToken] = useState('')
  const [register, setRegister] = useState({ email: '', password: '', tenant_name: '' })
  const [login, setLogin] = useState({ email: '', password: '', totp_code: '' })
  const [projects, setProjects] = useState([])
  const [projectName, setProjectName] = useState('')
  const [target, setTarget] = useState(initialTarget)
  const [targets, setTargets] = useState([])
  const [scanStatus, setScanStatus] = useState('')
  const [report, setReport] = useState('')
  const [apiKeys, setApiKeys] = useState([])
  const [apiKeyName, setApiKeyName] = useState('')
  const [newApiKey, setNewApiKey] = useState('')
  const [activeFeature, setActiveFeature] = useState(0)

  const features = [
    {
      title: 'Proof-of-authorization scanning',
      description: 'Require owner attestation or written authorization before any scan runs.'
    },
    {
      title: 'Safe, bounded checks',
      description: 'No DoS, no brute force, capped rate-limit validation with automatic backoff.'
    },
    {
      title: 'Actionable HTML reports',
      description: 'Executive summary, OWASP mappings, redacted evidence, and safe repro steps.'
    },
    {
      title: 'Multi-tenant projects',
      description: 'Separate projects, targets, and results per tenant with RBAC controls.'
    }
  ]

  const authHeaders = token ? { Authorization: `Bearer ${token}` } : {}

  const handleRegister = async () => {
    const res = await fetch(`${API_BASE}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(register)
    })
    const data = await res.json()
    setToken(data.access_token || '')
  }

  const handleLogin = async () => {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(login)
    })
    const data = await res.json()
    setToken(data.access_token || '')
  }

  const createProject = async () => {
    const res = await fetch(`${API_BASE}/projects`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders },
      body: JSON.stringify({ name: projectName })
    })
    const data = await res.json()
    setProjects([...projects, data])
    setProjectName('')
  }

  const loadTargets = async () => {
    const res = await fetch(`${API_BASE}/targets`, { headers: authHeaders })
    const data = await res.json()
    setTargets(data)
  }

  const createTarget = async () => {
    const payload = {
      ...target,
      allowlisted_hosts: target.allowlisted_hosts.split(',').map((h) => h.trim()),
      owner_attestation: true
    }
    const res = await fetch(`${API_BASE}/targets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders },
      body: JSON.stringify(payload)
    })
    const data = await res.json()
    setTargets([...targets, data])
    setTarget(initialTarget)
  }

  const startScan = async (targetId) => {
    const form = new FormData()
    form.append('target_id', targetId)
    const res = await fetch(`${API_BASE}/scans`, {
      method: 'POST',
      headers: authHeaders,
      body: form
    })
    const data = await res.json()
    setScanStatus(`Scan queued: ${data.id}`)
  }

  const fetchReport = async (scanId) => {
    const res = await fetch(`${API_BASE}/scans/${scanId}/report`, { headers: authHeaders })
    const data = await res.json()
    setReport(data.report_html || '')
  }

  const loadApiKeys = async () => {
    const res = await fetch(`${API_BASE}/auth/api-keys`, { headers: authHeaders })
    const data = await res.json()
    setApiKeys(data)
  }

  const createApiKey = async () => {
    const res = await fetch(`${API_BASE}/auth/api-keys`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders },
      body: JSON.stringify({ name: apiKeyName })
    })
    const data = await res.json()
    setNewApiKey(data.api_key || '')
    setApiKeyName('')
    loadApiKeys()
  }

  const revokeApiKey = async (apiKeyId) => {
    await fetch(`${API_BASE}/auth/api-keys/${apiKeyId}`, {
      method: 'DELETE',
      headers: authHeaders
    })
    loadApiKeys()
  }

  return (
    <div className="min-h-screen p-8">
      <header className="mb-12 rounded-2xl bg-gradient-to-br from-indigo-600 via-purple-600 to-rose-500 p-10 text-white shadow-xl">
        <div className="max-w-4xl">
          <p className="uppercase tracking-[0.3em] text-xs font-semibold text-indigo-100">Authorized API VAPT Scanner</p>
          <h1 className="mt-4 text-4xl font-bold md:text-5xl">Ethical, safe API security testing for the systems you own.</h1>
          <p className="mt-4 text-lg text-indigo-100">
            Run scoped scans, generate evidence-backed reports, and keep results accessible for 7 days. All data stays in the
            database for audit retention.
          </p>
          <div className="mt-6 flex flex-wrap gap-3">
            <span className="rounded-full bg-white/20 px-4 py-2 text-sm font-semibold">Free signup</span>
            <span className="rounded-full bg-white/20 px-4 py-2 text-sm font-semibold">Safe rate-limits</span>
            <span className="rounded-full bg-white/20 px-4 py-2 text-sm font-semibold">HTML reports</span>
          </div>
        </div>
      </header>

      <section className="mb-10 grid gap-6 md:grid-cols-2">
        <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">
          <h2 className="text-2xl font-semibold">What you can do</h2>
          <p className="mt-3 text-slate-300">
            Upload OpenAPI or Postman specs, enforce allowlists, and run safe checks for auth, validation, and data exposure.
          </p>
          <div className="mt-6 flex flex-wrap gap-2">
            {features.map((feature, index) => (
              <button
                key={feature.title}
                className={`rounded-full px-4 py-2 text-sm font-semibold transition ${
                  activeFeature === index ? 'bg-indigo-500 text-white' : 'bg-slate-800 text-slate-200'
                }`}
                onClick={() => setActiveFeature(index)}
              >
                {feature.title}
              </button>
            ))}
          </div>
          <div className="mt-6 rounded-xl bg-slate-800 p-4">
            <p className="text-lg font-semibold">{features[activeFeature].title}</p>
            <p className="mt-2 text-slate-300">{features[activeFeature].description}</p>
          </div>
        </div>
        <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">
          <h2 className="text-2xl font-semibold">How it works</h2>
          <ol className="mt-4 space-y-3 text-slate-300">
            <li className="flex gap-3">
              <span className="mt-1 h-2 w-2 rounded-full bg-emerald-400" />
              Create a project, add allowlisted targets, and confirm authorization.
            </li>
            <li className="flex gap-3">
              <span className="mt-1 h-2 w-2 rounded-full bg-emerald-400" />
              Start a scan and monitor safe, bounded checks.
            </li>
            <li className="flex gap-3">
              <span className="mt-1 h-2 w-2 rounded-full bg-emerald-400" />
              Review the HTML report, exported evidence, and fix guidance.
            </li>
          </ol>
          <div className="mt-6 rounded-xl bg-slate-800 p-4 text-sm text-slate-300">
            Results remain visible for <span className="font-semibold text-white">7 days</span>, then expire from user access while
            staying in the database for audit and compliance needs.
          </div>
        </div>
      </section>

      <section className="grid gap-6 md:grid-cols-2">
        <div className="bg-slate-900 p-6 rounded-lg">
          <h2 className="text-xl font-semibold mb-4">Register</h2>
          <div className="space-y-3">
            <input className="w-full p-2 rounded bg-slate-800" placeholder="Email" value={register.email} onChange={(e) => setRegister({ ...register, email: e.target.value })} />
            <input className="w-full p-2 rounded bg-slate-800" placeholder="Password" type="password" value={register.password} onChange={(e) => setRegister({ ...register, password: e.target.value })} />
            <input className="w-full p-2 rounded bg-slate-800" placeholder="Tenant name" value={register.tenant_name} onChange={(e) => setRegister({ ...register, tenant_name: e.target.value })} />
            <button className="bg-indigo-500 px-4 py-2 rounded" onClick={handleRegister}>Register & Sign In</button>
          </div>
        </div>
        <div className="bg-slate-900 p-6 rounded-lg">
          <h2 className="text-xl font-semibold mb-4">Login</h2>
          <div className="space-y-3">
            <input className="w-full p-2 rounded bg-slate-800" placeholder="Email" value={login.email} onChange={(e) => setLogin({ ...login, email: e.target.value })} />
            <input className="w-full p-2 rounded bg-slate-800" placeholder="Password" type="password" value={login.password} onChange={(e) => setLogin({ ...login, password: e.target.value })} />
            <input className="w-full p-2 rounded bg-slate-800" placeholder="TOTP (if enabled)" value={login.totp_code} onChange={(e) => setLogin({ ...login, totp_code: e.target.value })} />
            <button className="bg-emerald-500 px-4 py-2 rounded" onClick={handleLogin}>Login</button>
          </div>
        </div>
      </section>

      <section className="mt-8 bg-slate-900 p-6 rounded-lg">
        <h2 className="text-xl font-semibold mb-4">Projects</h2>
        <div className="flex gap-3">
          <input className="flex-1 p-2 rounded bg-slate-800" placeholder="Project name" value={projectName} onChange={(e) => setProjectName(e.target.value)} />
          <button className="bg-blue-500 px-4 py-2 rounded" onClick={createProject}>Create</button>
        </div>
        <ul className="mt-4 list-disc list-inside text-slate-300">
          {projects.map((project) => (
            <li key={project.id}>{project.name}</li>
          ))}
        </ul>
      </section>

      <section className="mt-8 bg-slate-900 p-6 rounded-lg">
        <h2 className="text-xl font-semibold mb-4">Targets</h2>
        <div className="grid gap-3 md:grid-cols-2">
          <input className="p-2 rounded bg-slate-800" placeholder="Target name" value={target.name} onChange={(e) => setTarget({ ...target, name: e.target.value })} />
          <input className="p-2 rounded bg-slate-800" placeholder="Base URL" value={target.base_url} onChange={(e) => setTarget({ ...target, base_url: e.target.value })} />
          <input className="p-2 rounded bg-slate-800" placeholder="Allowlisted hosts (comma-separated)" value={target.allowlisted_hosts} onChange={(e) => setTarget({ ...target, allowlisted_hosts: e.target.value })} />
          <input className="p-2 rounded bg-slate-800" placeholder="Auth header (e.g., x-api-key)" value={target.auth_header} onChange={(e) => setTarget({ ...target, auth_header: e.target.value })} />
          <input className="p-2 rounded bg-slate-800" placeholder="API key" value={target.api_key} onChange={(e) => setTarget({ ...target, api_key: e.target.value })} />
          <input className="p-2 rounded bg-slate-800" placeholder="Authorization text (optional)" value={target.authorization_text} onChange={(e) => setTarget({ ...target, authorization_text: e.target.value })} />
        </div>
        <div className="mt-4 flex gap-3">
          <button className="bg-indigo-500 px-4 py-2 rounded" onClick={createTarget}>Create target</button>
          <button className="bg-slate-700 px-4 py-2 rounded" onClick={loadTargets}>Refresh targets</button>
        </div>
        <ul className="mt-4 space-y-2">
          {targets.map((t) => (
            <li key={t.id} className="bg-slate-800 p-3 rounded flex justify-between">
              <span>{t.name} - {t.base_url}</span>
              <button className="bg-emerald-500 px-3 py-1 rounded" onClick={() => startScan(t.id)}>Start scan</button>
            </li>
          ))}
        </ul>
        {scanStatus && <p className="mt-4 text-slate-300">{scanStatus}</p>}
      </section>

      <section className="mt-8 bg-slate-900 p-6 rounded-lg">
        <h2 className="text-xl font-semibold mb-4">Download Report</h2>
        <div className="flex gap-3">
          <input className="flex-1 p-2 rounded bg-slate-800" placeholder="Scan ID" onBlur={(e) => fetchReport(e.target.value)} />
        </div>
        {report && (
          <div className="mt-4 bg-white text-black p-4 rounded" dangerouslySetInnerHTML={{ __html: report }} />
        )}
      </section>

      <section className="mt-8 bg-slate-900 p-6 rounded-lg">
        <h2 className="text-xl font-semibold mb-4">API Keys</h2>
        <p className="text-slate-300 mb-4">Generate a key for programmatic access. Keys are shown only once.</p>
        <div className="flex gap-3">
          <input className="flex-1 p-2 rounded bg-slate-800" placeholder="Key name" value={apiKeyName} onChange={(e) => setApiKeyName(e.target.value)} />
          <button className="bg-indigo-500 px-4 py-2 rounded" onClick={createApiKey}>Generate</button>
          <button className="bg-slate-700 px-4 py-2 rounded" onClick={loadApiKeys}>Refresh</button>
        </div>
        {newApiKey && (
          <div className="mt-4 bg-emerald-900 text-emerald-100 p-3 rounded">
            <p className="font-semibold">Your new API key:</p>
            <code className="break-all">{newApiKey}</code>
          </div>
        )}
        <ul className="mt-4 space-y-2">
          {apiKeys.map((key) => (
            <li key={key.id} className="bg-slate-800 p-3 rounded flex justify-between items-center">
              <div>
                <p className="font-semibold">{key.name}</p>
                <p className="text-slate-400 text-sm">Prefix: {key.prefix}</p>
              </div>
              <button className="bg-rose-500 px-3 py-1 rounded" onClick={() => revokeApiKey(key.id)}>Revoke</button>
            </li>
          ))}
        </ul>
      </section>
    </div>
  )
}
