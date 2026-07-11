import { useState } from 'react';
import { useAlert } from '../components/AlertProvider';

interface AuditLog {
  timestamp: string;
  user: string;
  action: string;
  resource: string;
  provider: 'AWS' | 'Azure' | 'GCP' | 'System';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

const INITIAL_LOGS: AuditLog[] = [
  { timestamp: '2026-07-03 15:20:12', user: 'admin_root', action: 'Trigger Scan', resource: 'AWS Production', provider: 'AWS', severity: 'info' },
  { timestamp: '2026-07-03 15:18:44', user: 'system', action: 'Auto Remediation Executed', resource: 'prod-user-data-assets', provider: 'AWS', severity: 'critical' },
  { timestamp: '2026-07-03 15:15:30', user: 'sec_analyst_01', action: 'Suppress Finding', resource: 'NET-981 / default-sg', provider: 'Azure', severity: 'medium' },
  { timestamp: '2026-07-03 15:10:05', user: 'admin_root', action: 'Update Cloud Credentials', resource: 'GCP Data Platform', provider: 'GCP', severity: 'high' },
  { timestamp: '2026-07-03 15:08:21', user: 'system', action: 'Account Validation Failed', resource: 'GCP Data Platform', provider: 'GCP', severity: 'high' },
  { timestamp: '2026-07-03 14:55:12', user: 'admin_root', action: 'Generate API Key', resource: 'IAM User Key', provider: 'System', severity: 'medium' },
  { timestamp: '2026-07-03 14:32:00', user: 'sec_analyst_02', action: 'Remediation Step Initiated', resource: 'rds-cluster-primary', provider: 'AWS', severity: 'medium' },
  { timestamp: '2026-07-03 14:15:10', user: 'system', action: 'Compliance Benchmark Completed', resource: 'SOC 2 Audit', provider: 'System', severity: 'info' },
];

const LogsPage = () => {
  const { showAlert } = useAlert();
  const [logs, setLogs] = useState<AuditLog[]>(INITIAL_LOGS);
  const [search, setSearch] = useState('');
  const [sevFilter, setSevFilter] = useState('All');
  const [providerFilter, setProviderFilter] = useState('All');

  const filteredLogs = logs.filter((log) => {
    const matchesSearch =
      log.action.toLowerCase().includes(search.toLowerCase()) ||
      log.user.toLowerCase().includes(search.toLowerCase()) ||
      log.resource.toLowerCase().includes(search.toLowerCase());
    const matchesSev = sevFilter === 'All' || log.severity === sevFilter.toLowerCase();
    const matchesProvider = providerFilter === 'All' || log.provider === providerFilter;
    return matchesSearch && matchesSev && matchesProvider;
  });

  const handleExportLogs = () => {
    const headers = ['Timestamp', 'User', 'Action', 'Resource', 'Provider', 'Severity'];
    const rows = filteredLogs.map((log) => [
      log.timestamp, log.user, log.action, log.resource, log.provider, log.severity,
    ]);
    const csvContent = [headers, ...rows]
      .map((row) => row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(','))
      .join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `cspm-audit-logs-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    showAlert('success', 'Audit Logs Exported', `Downloaded ${filteredLogs.length} log entries as CSV.`);
  };

  const handleClearLogs = () => {
    setLogs([]);
    showAlert('warning', 'Logs Cleared', 'Audit log display cleared. Local history is not deleted.');
  };

  const handleAddDemoLog = () => {
    const newLog: AuditLog = {
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
      user: 'admin_root',
      action: 'Ad-hoc Scan Started',
      resource: 'Manual Validation',
      provider: 'System',
      severity: 'info',
    };
    setLogs((prev) => [newLog, ...prev]);
    showAlert('info', 'New Audit Entry', 'Added a demo system audit log entry.');
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'critical':
        return 'bg-error/15 text-error border-error/20';
      case 'high':
        return 'bg-tertiary/15 text-tertiary border-tertiary/20';
      case 'medium':
        return 'bg-primary/15 text-primary border-primary/20';
      case 'low':
        return 'bg-secondary/15 text-secondary border-secondary/20';
      default:
        return 'bg-outline/15 text-on-surface-variant border-outline/20';
    }
  };

  const getProviderIcon = (provider: string) => {
    switch (provider) {
      case 'AWS':
        return 'cloud';
      case 'Azure':
        return 'grid_view';
      case 'GCP':
        return 'api';
      default:
        return 'computer';
    }
  };

  return (
    <main className="pt-16 pb-20 px-4 md:px-6 max-w-7xl mx-auto space-y-6">
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
        <div>
          <h1 className="font-headline-lg text-headline-lg text-on-surface">Audit Logs</h1>
          <p className="text-body-md text-on-surface-variant mt-1">
            System audit trail mapping all actions, remediations, and user interactions.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleAddDemoLog}
            className="bg-surface-container-high border border-outline-variant/20 text-on-surface hover:bg-surface-variant font-bold px-4 py-2 rounded-lg text-sm transition-all"
          >
            Add Demo Entry
          </button>
          <button
            onClick={handleClearLogs}
            className="bg-error-container/20 text-error border border-error/30 hover:bg-error/15 font-bold px-4 py-2 rounded-lg text-sm transition-all"
          >
            Clear View
          </button>
          <button
            onClick={handleExportLogs}
            className="bg-primary text-on-primary hover:brightness-110 font-bold px-4 py-2 rounded-lg text-sm transition-all flex items-center gap-2"
          >
            <span className="material-symbols-outlined text-sm">download</span> Export CSV
          </button>
        </div>
      </div>

      <section className="glass-panel rounded-xl overflow-hidden flex flex-col">
        {/* Toolbar */}
        <div className="p-4 border-b border-outline-variant/20 flex flex-wrap items-center gap-4 bg-surface-container">
          <div className="relative flex-1 min-w-[280px]">
            <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant text-sm">
              search
            </span>
            <input
              type="text"
              className="w-full bg-surface-container-lowest border border-outline-variant/20 rounded-lg pl-10 pr-4 py-2 text-body-md focus:outline-none focus:border-primary transition-all text-on-surface"
              placeholder="Search logs by action, user, or resource..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <div className="flex items-center gap-2">
            <select
              className="bg-surface-container-lowest border border-outline-variant/20 rounded-lg px-3 py-2 text-body-sm focus:outline-none focus:border-primary text-on-surface"
              value={sevFilter}
              onChange={(e) => setSevFilter(e.target.value)}
            >
              <option>All Severities</option>
              <option>Critical</option>
              <option>High</option>
              <option>Medium</option>
              <option>Low</option>
              <option>Info</option>
            </select>
            <select
              className="bg-surface-container-lowest border border-outline-variant/20 rounded-lg px-3 py-2 text-body-sm focus:outline-none focus:border-primary text-on-surface"
              value={providerFilter}
              onChange={(e) => setProviderFilter(e.target.value)}
            >
              <option>All Providers</option>
              <option>AWS</option>
              <option>Azure</option>
              <option>GCP</option>
              <option>System</option>
            </select>
          </div>
        </div>

        {/* Logs Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse min-w-[900px]">
            <thead>
              <tr className="bg-surface-container-high border-b border-outline-variant/20">
                <th className="px-6 py-3 font-label-caps text-label-caps text-on-surface-variant">Timestamp</th>
                <th className="px-6 py-3 font-label-caps text-label-caps text-on-surface-variant">Actor / User</th>
                <th className="px-6 py-3 font-label-caps text-label-caps text-on-surface-variant">Action</th>
                <th className="px-6 py-3 font-label-caps text-label-caps text-on-surface-variant">Resource Scope</th>
                <th className="px-6 py-3 font-label-caps text-label-caps text-on-surface-variant">Provider</th>
                <th className="px-6 py-3 font-label-caps text-label-caps text-on-surface-variant text-right">Severity</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-outline-variant/10 font-mono-data text-body-sm">
              {filteredLogs.length > 0 ? (
                filteredLogs.map((log, index) => (
                  <tr key={index} className="hover:bg-primary/5 transition-colors group">
                    <td className="px-6 py-3 text-on-surface-variant">{log.timestamp}</td>
                    <td className="px-6 py-3 text-on-surface font-semibold">{log.user}</td>
                    <td className="px-6 py-3 text-on-surface font-bold text-sm">{log.action}</td>
                    <td className="px-6 py-3 text-on-surface-variant">{log.resource}</td>
                    <td className="px-6 py-3">
                      <div className="flex items-center gap-2">
                        <span className="material-symbols-outlined text-sm text-primary">
                          {getProviderIcon(log.provider)}
                        </span>
                        <span className="text-on-surface">{log.provider}</span>
                      </div>
                    </td>
                    <td className="px-6 py-3 text-right">
                      <span className={`px-2.5 py-0.5 rounded border text-[10px] uppercase font-bold tracking-wider ${getSeverityBadge(log.severity)}`}>
                        {log.severity}
                      </span>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="px-6 py-8 text-center text-on-surface-variant font-body-md">
                    No matching audit logs found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </main>
  );
};

export default LogsPage;
