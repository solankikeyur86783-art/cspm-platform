import { useState, useEffect } from 'react';
import { useAlert } from '../components/AlertProvider';
import GlobeMap from '../components/GlobeMap';

interface ThreatEvent {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  code: string;
  time: string;
  description: string;
  location: string;
  resource: string;
  ip?: string;
  user?: string;
  tags?: string[];
  remediationSteps?: string;
}

const INITIAL_THREAT_EVENTS: ThreatEvent[] = [
  {
    id: 'IAM-042',
    severity: 'critical',
    title: 'Anomalous Login Detected',
    code: 'Critical Severity',
    time: 'Just Now',
    description: 'User admin_root logged in from 185.220.101.42 (Tor Exit Node).',
    location: 'US-EAST-1',
    resource: 'PROD-ENV',
    ip: '185.220.101.42',
    user: 'admin_root',
    tags: ['US-EAST-1', 'PROD-ENV'],
    remediationSteps: 'Disable compromised API credential. Revoke active session tokens. Enforce MFA validation immediately.',
  },
  {
    id: 'NET-881',
    severity: 'high',
    title: 'Suspicious API Activity',
    code: 'High Severity',
    time: '4m ago',
    description: 'Rapid enumeration of DescribeInstances on VPC-99812-XX.',
    location: 'US-EAST-1',
    resource: 'i-0f92bc4911d3',
    remediationSteps: 'Restrict IAM assume-role policies. Terminate EC2 instance role metadata access and review CloudTrail histories.',
  },
  {
    id: 'S3-102',
    severity: 'medium',
    title: 'S3 Bucket Policy Change',
    code: 'Medium Severity',
    time: '18m ago',
    description: 'Public read access granted to sentinel-audit-logs-2023 by User: Jenkins_CI.',
    location: 'US-WEST-2',
    resource: 'sentinel-audit-logs-2023',
    remediationSteps: 'Revert S3 Public Access block. Audit Jenkins CI credential privileges and force private bucket configurations.',
  },
  {
    id: 'IAM-011',
    severity: 'low',
    title: 'Unused Access Key Rotation',
    code: 'Low Severity',
    time: '42m ago',
    description: 'Access key AKIA...44B has not been used in 90 days.',
    location: 'GLOBAL',
    resource: 'AKIA...44B',
    remediationSteps: 'Disable the access key using IAM console or AWS CLI. Notify the credentials owner about automatic cleanup.',
  },
];

const ThreatsPage = () => {
  const { showAlert } = useAlert();
  const [threatEvents, setThreatEvents] = useState<ThreatEvent[]>(INITIAL_THREAT_EVENTS);
  const [refreshTimer, setRefreshTimer] = useState(5);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState('All');
  const [investigatingEvent, setInvestigatingEvent] = useState<string | null>(null);

  const riskDistribution = [
    { label: 'CRITICAL EVENTS', percentage: 24, color: 'bg-error' },
    { label: 'HIGH EVENTS', percentage: 42, color: 'bg-tertiary' },
    { label: 'REMEDIED TODAY', percentage: 68, color: 'bg-secondary' },
  ];

  const resourcesUnderPressure = [
    { name: 'ec2-prod-gateway', alerts: 14, alertColor: 'error' },
    { name: 's3-bucket-customer-data', alerts: 8, alertColor: 'tertiary' },
    { name: 'rds-cluster-primary', alerts: 3, alertColor: 'primary' },
  ];

  useEffect(() => {
    const timer = setInterval(() => {
      setRefreshTimer((prev) => {
        if (prev <= 1) {
          // Trigger a silent threat update demo
          return 5;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const handleRemediate = (id: string) => {
    showAlert('success', 'Remediation Queued', `Triggering automated playbook remediation for ${id}.`);
    setTimeout(() => {
      showAlert('success', 'Playbook Applied', `Event ${id} has been resolved and removed from active threat logs.`);
      setThreatEvents((prev) => prev.filter((e) => e.id !== id));
    }, 2500);
  };

  const handleMute = (id: string) => {
    showAlert('warning', 'Threat Muted', `Event ${id} is suppressed and silenced for 24 hours.`);
    setThreatEvents((prev) => prev.filter((e) => e.id !== id));
  };

  const handleDismiss = (id: string) => {
    showAlert('info', 'Case Dismissed', `Dismissed threat incident report ${id}.`);
    setThreatEvents((prev) => prev.filter((e) => e.id !== id));
  };

  const handleInvestigate = (id: string) => {
    setInvestigatingEvent((prev) => (prev === id ? null : id));
    showAlert('info', 'Investigating Case', `Displaying mitigation instructions and audit paths for ${id}.`);
  };

  const handleExport = () => {
    showAlert('success', 'Export Success', 'Threat intelligence log report generated.');
  };

  const handleLoadPrevious = () => {
    showAlert('info', 'Loading Archive', 'Fetching older historical events from CloudTrail archive log data...');
  };

  const handleSubmitCaseFAB = () => {
    showAlert('success', 'Case Submitted', 'New threat incident case lodged with the security operation center team.');
  };

  const getSeverityStyles = (severity: string) => {
    switch (severity) {
      case 'critical':
        return {
          border: 'severity-critical',
          glow: 'glow-critical',
          iconBg: 'bg-error-container/20',
          iconColor: 'text-error',
          textColor: 'text-error',
        };
      case 'high':
        return {
          border: 'severity-high',
          glow: '',
          iconBg: 'bg-tertiary-container/20',
          iconColor: 'text-tertiary',
          textColor: 'text-tertiary',
        };
      case 'medium':
        return {
          border: 'severity-medium',
          glow: '',
          iconBg: 'bg-primary-container/20',
          iconColor: 'text-primary',
          textColor: 'text-primary',
        };
      default:
        return {
          border: 'severity-low',
          glow: '',
          iconBg: 'bg-secondary-container/20',
          iconColor: 'text-secondary',
          textColor: 'text-secondary',
        };
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'gpp_maybe';
      case 'high':
        return 'api';
      case 'medium':
        return 'storage';
      default:
        return 'update';
    }
  };

  const filteredEvents = threatEvents.filter((event) => {
    const matchesSearch =
      event.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      event.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      event.description.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesSeverity = selectedSeverity === 'All' || event.severity === selectedSeverity.toLowerCase();
    return matchesSearch && matchesSeverity;
  });

  return (
    <main className="pt-16 pb-20 px-4 md:px-6 max-w-7xl mx-auto space-y-6">
      {/* Header Section */}
      <section className="flex flex-col md:flex-row md:items-end justify-between gap-4">
        <div>
          <h1 className="font-headline-lg text-headline-lg text-on-surface">Threat Intelligence</h1>
          <p className="font-body-md text-body-md text-on-surface-variant">
            Real-time surveillance of global infrastructure anomalies.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex -space-x-2">
            <div className="w-8 h-8 rounded-full border-2 border-surface-container overflow-hidden bg-surface-container-high flex items-center justify-center font-bold text-xs text-primary">
              A
            </div>
            <div className="w-8 h-8 rounded-full border-2 border-surface-container bg-primary-container text-on-primary-container flex items-center justify-center font-label-caps text-[10px]">
              +3
            </div>
          </div>
          <span className="font-label-caps text-label-caps text-on-surface-variant uppercase">
            4 Analysts Active
          </span>
        </div>
      </section>

      {/* Search & Filter Bar */}
      <div className="bg-surface-container-low border border-outline-variant/20 rounded-xl p-3 flex flex-wrap items-center gap-4">
        <div className="flex-1 min-w-[280px] relative">
          <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-outline text-sm">
            search
          </span>
          <input
            type="text"
            className="w-full bg-surface-container-lowest border-none rounded-lg pl-10 pr-4 py-2 font-body-md text-on-surface focus:ring-1 focus:ring-primary"
            placeholder="Search events, resource IDs, or actors..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
        <div className="flex gap-2">
          <select
            value={selectedSeverity}
            onChange={(e) => {
              setSelectedSeverity(e.target.value);
              showAlert('info', 'Filter Switched', `Filter applied: ${e.target.value} severity.`);
            }}
            className="bg-surface-container-high border border-outline-variant/20 rounded-lg px-3 py-2 text-body-sm text-on-surface focus:outline-none"
          >
            <option>All</option>
            <option>Critical</option>
            <option>High</option>
            <option>Medium</option>
            <option>Low</option>
          </select>
          <button
            onClick={handleExport}
            className="flex items-center gap-2 px-4 py-2 bg-primary text-on-primary rounded-lg font-bold text-sm hover:brightness-110 transition-all"
          >
            <span className="material-symbols-outlined text-sm">download</span>
            <span>Export</span>
          </button>
        </div>
      </div>

      {/* Dashboard Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Activity Feed (Left Column) */}
        <div className="lg:col-span-8 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="font-headline-sm text-headline-sm text-on-surface flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-secondary animate-pulse"></span>
              Live Detection Feed
            </h2>
            <span className="font-mono-data text-mono-data text-secondary">AUTO-REFRESH: {refreshTimer}s</span>
          </div>

          <div className="space-y-3">
            {filteredEvents.length > 0 ? (
              filteredEvents.map((event) => {
                const styles = getSeverityStyles(event.severity);
                const isExpanded = investigatingEvent === event.id;

                return (
                  <div
                    key={event.id}
                    className={`bg-surface-container-low border border-outline-variant/10 rounded-lg p-4 ${styles.border} ${styles.glow} transition-all hover:bg-surface-container-high group`}
                  >
                    <div className="flex justify-between items-start mb-2">
                      <div className="flex items-center gap-3">
                        <div className={`${styles.iconBg} p-2 rounded-lg`}>
                          <span
                            className={`material-symbols-outlined ${styles.iconColor}`}
                            style={event.severity === 'critical' ? { fontVariationSettings: "'FILL' 1" } : {}}
                          >
                            {getSeverityIcon(event.severity)}
                          </span>
                        </div>
                        <div>
                          <h3 className="font-headline-sm text-[16px] text-on-surface">{event.title}</h3>
                          <p
                            className={`font-mono-data text-mono-data ${styles.textColor} uppercase text-[10px] tracking-widest mt-0.5`}
                          >
                            {event.code} • {event.id}
                          </p>
                        </div>
                      </div>
                      <span className="font-mono-data text-mono-data text-on-surface-variant text-[11px]">
                        {event.time}
                      </span>
                    </div>

                    <div className="ml-12 space-y-2">
                      <p className="font-body-sm text-on-surface-variant leading-relaxed">
                        {event.description}
                      </p>

                      {event.tags && (
                        <div className="flex items-center gap-2">
                          {event.tags.map((tag, idx) => (
                            <span
                              key={idx}
                              className="font-label-caps text-[9px] text-outline px-1.5 py-0.5 border border-outline-variant/30 rounded"
                            >
                              {tag}
                            </span>
                          ))}
                        </div>
                      )}

                      {/* Action buttons bar */}
                      <div className="flex items-center gap-2 pt-2">
                        <button
                          onClick={() => handleInvestigate(event.id)}
                          className="px-3 py-1.5 bg-surface-container-highest border border-outline-variant/20 rounded hover:border-primary transition-colors font-label-caps text-on-surface text-[11px]"
                        >
                          {isExpanded ? 'CLOSE MITIGATION' : 'MITIGATION STEPS'}
                        </button>
                        <button
                          onClick={() => handleMute(event.id)}
                          className="px-3 py-1.5 bg-surface-container-highest border border-outline-variant/20 rounded hover:border-primary transition-colors font-label-caps text-on-surface text-[11px]"
                        >
                          MUTE
                        </button>
                        <button
                          onClick={() => handleDismiss(event.id)}
                          className="px-3 py-1.5 bg-surface-container-highest border border-outline-variant/20 rounded hover:border-primary transition-colors font-label-caps text-on-surface text-[11px]"
                        >
                          DISMISS
                        </button>
                        <button
                          onClick={() => handleRemediate(event.id)}
                          className="px-3 py-1.5 bg-primary text-on-primary rounded font-label-caps text-[11px] hover:brightness-110 ml-auto"
                        >
                          REMEDIATE
                        </button>
                      </div>

                      {/* Expanded Mitigation Step details */}
                      {isExpanded && (
                        <div className="p-3 bg-surface-container-high rounded-lg border border-outline-variant/25 mt-3 animate-pulse-soft text-xs space-y-2">
                          <div className="font-bold text-primary flex items-center gap-1.5">
                            <span className="material-symbols-outlined text-sm">construction</span>
                            HOW TO MITIGATE
                          </div>
                          <p className="text-on-surface-variant leading-relaxed">
                            {event.remediationSteps}
                          </p>
                          <div className="text-[10px] text-outline italic">
                            Audited against Security Control framework guidelines.
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                );
              })
            ) : (
              <div className="p-8 text-center text-on-surface-variant font-body-md bg-surface-container-low border border-outline-variant/10 rounded-lg">
                No active threats fit selected queries.
              </div>
            )}
          </div>

          <button
            onClick={handleLoadPrevious}
            className="w-full py-3 bg-surface-container-lowest border border-dashed border-outline-variant/30 rounded-lg font-label-caps text-outline hover:border-primary hover:text-primary transition-all text-xs"
          >
            LOAD PREVIOUS EVENTS
          </button>
        </div>

        {/* Sidebar Insights (Right Column) */}
        <div className="lg:col-span-4 space-y-6">
          {/* 3D Cyber Threat Globe */}
          <div className="bg-surface-container border border-outline-variant/20 rounded-xl overflow-hidden">
            <div className="p-4 border-b border-outline-variant/10 flex justify-between items-center bg-surface-container-high">
              <h3 className="font-label-caps text-label-caps text-on-surface uppercase tracking-widest">
                Interactive Threat Globe
              </h3>
              <span className="material-symbols-outlined text-on-surface-variant text-[20px] animate-pulse text-secondary">
                public
              </span>
            </div>
            <div className="relative aspect-square w-full bg-surface-container-lowest">
              <GlobeMap className="absolute inset-0" />
            </div>
          </div>

          {/* Global Risk Distribution Card */}
          <div className="bg-surface-container border border-outline-variant/20 rounded-xl">
            <div className="p-4 border-b border-outline-variant/10 bg-surface-container-high">
              <h3 className="font-label-caps text-label-caps text-on-surface uppercase tracking-widest">
                Global Risk Distribution
              </h3>
            </div>
            <div className="p-4 space-y-4">
              <div className="space-y-3">
                {riskDistribution.map((item, index) => (
                  <div key={index}>
                    <div className="flex justify-between font-label-caps text-[10px] text-on-surface-variant mb-1">
                      <span>{item.label}</span>
                      <span>{item.percentage}%</span>
                    </div>
                    <div className="h-1.5 w-full bg-surface-variant rounded-full overflow-hidden">
                      <div
                        className={`h-full ${item.color} rounded-full`}
                        style={{ width: `${item.percentage}%` }}
                      ></div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Resources Under Pressure Card */}
          <div className="bg-surface-container border border-outline-variant/20 rounded-xl">
            <div className="p-4 border-b border-outline-variant/10 bg-surface-container-high">
              <h3 className="font-label-caps text-label-caps text-on-surface uppercase tracking-widest">
                Resources Under Pressure
              </h3>
            </div>
            <div className="p-2 space-y-1">
              {resourcesUnderPressure.map((resource, index) => (
                <div
                  key={index}
                  className="flex items-center justify-between p-2 hover:bg-surface-variant/30 rounded-lg cursor-pointer group"
                  onClick={() => showAlert('info', 'Resource Audit Scope', `Highlighting risk details for ${resource.name}`)}
                >
                  <div className="flex items-center gap-3">
                    <span className="font-mono-data text-outline text-[10px]">
                      {String(index + 1).padStart(2, '0')}
                    </span>
                    <span className="font-mono-data text-body-sm text-on-surface">{resource.name}</span>
                  </div>
                  <span
                    className={`font-mono-data text-[10px] px-2 py-0.5 rounded border bg-${resource.alertColor}/10 text-${resource.alertColor} border-${resource.alertColor}/20`}
                  >
                    {resource.alerts} ALERTS
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Floating Action Button */}
      <button
        onClick={handleSubmitCaseFAB}
        className="fixed bottom-8 right-8 hidden md:flex items-center gap-3 bg-primary text-on-primary px-6 py-4 rounded-full shadow-2xl hover:scale-105 transition-all group z-40"
      >
        <span className="material-symbols-outlined" style={{ fontVariationSettings: "'FILL' 1" }}>
          add_alert
        </span>
        <span className="font-headline-sm text-xs font-bold uppercase tracking-tighter">Submit Threat Case</span>
      </button>
    </main>
  );
};

export default ThreatsPage;
