import { useState, useEffect, useCallback } from 'react'
import './App.css'

// API base URL
const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

// WebSocket URL
const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000/ws'

function App() {
  const [stats, setStats] = useState(null)
  const [violations, setViolations] = useState([])
  const [auditLogs, setAuditLogs] = useState([])
  const [policies, setPolicies] = useState([])
  const [rules, setRules] = useState([])
  const [activeTab, setActiveTab] = useState('dashboard')
  const [wsConnected, setWsConnected] = useState(false)
  const [error, setError] = useState(null)

  // Fetch stats
  const fetchStats = useCallback(async () => {
    try {
      const response = await fetch(`${API_URL}/api/stats`)
      if (!response.ok) throw new Error('Failed to fetch stats')
      const data = await response.json()
      setStats(data)
      setError(null)
    } catch (err) {
      setError(err.message)
    }
  }, [])

  // Fetch violations
  const fetchViolations = useCallback(async () => {
    try {
      const response = await fetch(`${API_URL}/api/violations?limit=50`)
      if (!response.ok) throw new Error('Failed to fetch violations')
      const data = await response.json()
      setViolations(data.violations || [])
    } catch (err) {
      console.error('Failed to fetch violations:', err)
    }
  }, [])

  // Fetch audit logs
  const fetchAuditLogs = useCallback(async () => {
    try {
      const response = await fetch(`${API_URL}/api/audit?limit=50`)
      if (!response.ok) throw new Error('Failed to fetch audit logs')
      const data = await response.json()
      setAuditLogs(data.entries || [])
    } catch (err) {
      console.error('Failed to fetch audit logs:', err)
    }
  }, [])

  // Fetch policies
  const fetchPolicies = useCallback(async () => {
    try {
      const response = await fetch(`${API_URL}/api/policies`)
      if (!response.ok) throw new Error('Failed to fetch policies')
      const data = await response.json()
      setPolicies(data.policies || [])
    } catch (err) {
      console.error('Failed to fetch policies:', err)
    }
  }, [])

  // Fetch rules
  const fetchRules = useCallback(async () => {
    try {
      const response = await fetch(`${API_URL}/api/rules`)
      if (!response.ok) throw new Error('Failed to fetch rules')
      const data = await response.json()
      setRules(data.rules || [])
    } catch (err) {
      console.error('Failed to fetch rules:', err)
    }
  }, [])

  // WebSocket connection
  useEffect(() => {
    const ws = new WebSocket(WS_URL)

    ws.onopen = () => {
      console.log('WebSocket connected')
      setWsConnected(true)
    }

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data)
      if (data.type === 'stats') {
        setStats(data.data)
      }
    }

    ws.onclose = () => {
      console.log('WebSocket disconnected')
      setWsConnected(false)
    }

    ws.onerror = (error) => {
      console.error('WebSocket error:', error)
      setWsConnected(false)
    }

    return () => {
      ws.close()
    }
  }, [])

  // Initial data fetch
  useEffect(() => {
    fetchStats()
    fetchViolations()
    fetchAuditLogs()
    fetchPolicies()
    fetchRules()

    // Refresh every 5 seconds
    const interval = setInterval(() => {
      fetchStats()
      if (activeTab === 'violations') fetchViolations()
      if (activeTab === 'audit') fetchAuditLogs()
    }, 5000)

    return () => clearInterval(interval)
  }, [activeTab, fetchStats, fetchViolations, fetchAuditLogs])

  const getSeverityBadgeClass = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'badge-critical'
      case 'high': return 'badge-high'
      case 'medium': return 'badge-medium'
      case 'low': return 'badge-low'
      default: return 'badge-medium'
    }
  }

  const formatTimestamp = (timestamp) => {
    if (!timestamp) return 'N/A'
    const date = new Date(timestamp)
    return date.toLocaleString()
  }

  return (
    <div className="min-h-screen bg-slate-900">
      {/* Header */}
      <header className="bg-slate-800 border-b border-slate-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center">
              <h1 className="text-xl font-bold text-white">
                Agent Constitution Dashboard
              </h1>
            </div>
            <div className="flex items-center space-x-4">
              <div className={`flex items-center space-x-2 ${wsConnected ? 'text-green-400' : 'text-red-400'}`}>
                <span className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-green-400' : 'bg-red-400'}`}></span>
                <span className="text-sm">{wsConnected ? 'Connected' : 'Disconnected'}</span>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Navigation */}
      <nav className="bg-slate-800 border-b border-slate-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex space-x-8">
            {['dashboard', 'violations', 'audit', 'policies', 'rules'].map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`py-4 px-1 border-b-2 font-medium text-sm capitalize ${
                  activeTab === tab
                    ? 'border-primary-500 text-primary-400'
                    : 'border-transparent text-slate-400 hover:text-slate-300 hover:border-slate-300'
                }`}
              >
                {tab}
              </button>
            ))}
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {error && (
          <div className="mb-4 p-4 bg-red-900/50 border border-red-700 rounded-lg text-red-200">
            Error: {error}
          </div>
        )}

        {/* Dashboard Tab */}
        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            <h2 className="text-2xl font-bold text-white">Dashboard Overview</h2>
            
            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <div className="stat-card">
                <span className="stat-value">{stats?.violations?.total || 0}</span>
                <span className="stat-label">Total Violations</span>
              </div>
              <div className="stat-card">
                <span className="stat-value">{stats?.audit?.total_entries || 0}</span>
                <span className="stat-label">Audit Entries</span>
              </div>
              <div className="stat-card">
                <span className="stat-value">{stats?.constitution?.policies_count || 0}</span>
                <span className="stat-label">Policies</span>
              </div>
              <div className="stat-card">
                <span className="stat-value">{stats?.constitution?.rules_count || 0}</span>
                <span className="stat-label">Rules</span>
              </div>
            </div>

            {/* Constitution Info */}
            {stats?.constitution && (
              <div className="card">
                <h3 className="text-lg font-semibold text-white mb-2">
                  {stats.constitution.name}
                </h3>
                <p className="text-slate-400">Version: {stats.constitution.version}</p>
              </div>
            )}

            {/* Violations by Severity */}
            {stats?.violations?.by_severity && Object.keys(stats.violations.by_severity).length > 0 && (
              <div className="card">
                <h3 className="text-lg font-semibold text-white mb-4">Violations by Severity</h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  {Object.entries(stats.violations.by_severity).map(([severity, count]) => (
                    <div key={severity} className="text-center p-4 bg-slate-700/50 rounded-lg">
                      <div className="text-2xl font-bold text-white">{count}</div>
                      <div className={`text-sm capitalize ${getSeverityBadgeClass(severity).replace('badge-', 'text-')}`}>
                        {severity}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Violations Tab */}
        {activeTab === 'violations' && (
          <div className="space-y-6">
            <h2 className="text-2xl font-bold text-white">Policy Violations</h2>
            
            {violations.length === 0 ? (
              <div className="card text-center py-12">
                <p className="text-slate-400">No violations recorded</p>
              </div>
            ) : (
              <div className="table-container">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Rule</th>
                      <th>Severity</th>
                      <th>Action</th>
                      <th>Timestamp</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-700">
                    {violations.map((violation, index) => (
                      <tr key={index}>
                        <td>
                          <div className="font-medium text-white">{violation.rule_name}</div>
                          <div className="text-sm text-slate-400">{violation.rule_description}</div>
                        </td>
                        <td>
                          <span className={getSeverityBadgeClass(violation.severity)}>
                            {violation.severity}
                          </span>
                        </td>
                        <td className="capitalize">{violation.action}</td>
                        <td>{formatTimestamp(violation.timestamp)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* Audit Tab */}
        {activeTab === 'audit' && (
          <div className="space-y-6">
            <h2 className="text-2xl font-bold text-white">Audit Logs</h2>
            
            {auditLogs.length === 0 ? (
              <div className="card text-center py-12">
                <p className="text-slate-400">No audit entries</p>
              </div>
            ) : (
              <div className="table-container">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Timestamp</th>
                      <th>Event Type</th>
                      <th>Tool</th>
                      <th>Action</th>
                      <th>Allowed</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-700">
                    {auditLogs.map((entry, index) => (
                      <tr key={index}>
                        <td>{formatTimestamp(entry.timestamp)}</td>
                        <td className="capitalize">{entry.event_type}</td>
                        <td>{entry.tool_name || 'N/A'}</td>
                        <td className="capitalize">{entry.action}</td>
                        <td>
                          <span className={`badge ${entry.allowed ? 'badge-low' : 'badge-critical'}`}>
                            {entry.allowed ? 'Yes' : 'No'}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* Policies Tab */}
        {activeTab === 'policies' && (
          <div className="space-y-6">
            <h2 className="text-2xl font-bold text-white">Policies</h2>
            
            {policies.length === 0 ? (
              <div className="card text-center py-12">
                <p className="text-slate-400">No policies loaded</p>
              </div>
            ) : (
              <div className="grid gap-4">
                {policies.map((policy, index) => (
                  <div key={index} className="card">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-lg font-semibold text-white">{policy.name}</h3>
                        <p className="text-slate-400">{policy.description}</p>
                      </div>
                      <div className="flex items-center space-x-4">
                        <span className={`badge ${policy.enabled ? 'badge-low' : 'badge-medium'}`}>
                          {policy.enabled ? 'Enabled' : 'Disabled'}
                        </span>
                        <span className="text-slate-400">Priority: {policy.priority}</span>
                        <span className="text-slate-400">{policy.rules_count} rules</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Rules Tab */}
        {activeTab === 'rules' && (
          <div className="space-y-6">
            <h2 className="text-2xl font-bold text-white">Rules</h2>
            
            {rules.length === 0 ? (
              <div className="card text-center py-12">
                <p className="text-slate-400">No rules defined</p>
              </div>
            ) : (
              <div className="grid gap-4">
                {rules.map((rule, index) => (
                  <div key={index} className="card">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center space-x-3">
                          <h3 className="text-lg font-semibold text-white">{rule.name}</h3>
                          <span className={getSeverityBadgeClass(rule.severity)}>
                            {rule.severity}
                          </span>
                          <span className={`badge ${rule.enabled ? 'badge-low' : 'badge-medium'}`}>
                            {rule.enabled ? 'Enabled' : 'Disabled'}
                          </span>
                        </div>
                        <p className="text-slate-400 mt-1">{rule.description}</p>
                        <div className="mt-2 text-sm text-slate-500">
                          Policy: {rule.policy}
                        </div>
                        <div className="mt-2 p-2 bg-slate-900 rounded text-sm font-mono text-slate-400">
                          Condition: {rule.condition}
                        </div>
                      </div>
                      <div className="ml-4">
                        <span className="badge badge-medium capitalize">{rule.action}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  )
}

export default App
