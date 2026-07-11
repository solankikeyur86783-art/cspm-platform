import { useState, useRef } from 'react';
import { useAlert } from '../components/AlertProvider';
import { AreaChart, DonutChart, Sparkline } from '../components/Charts';

const OverviewPage = () => {
  const { showAlert } = useAlert();
  const findingsContainerRef = useRef<HTMLDivElement>(null);
  const [showFixModal, setShowFixModal] = useState<string | null>(null);

  const criticalFindings = [
    {
      id: 'SEC-042',
      title: 'S3 Bucket Publicly Accessible',
      description: "Bucket 'prod-user-data-assets' has public read/write permissions via ACL.",
      severity: 'critical',
      provider: 'AWS',
      region: 'us-east-1',
      icon: 'cloud',
    },
    {
      id: 'NET-981',
      title: 'Unrestricted SSH Access',
      description: "Security Group 'default-sg' allows port 22 from 0.0.0.0/0 on 14 sensitive instances.",
      severity: 'critical',
      provider: 'Azure',
      region: 'West Europe',
      icon: 'lan',
    },
    {
      id: 'IAM-115',
      title: 'Root User Lack of MFA',
      description: 'The master billing account root user does not have Multi-Factor Authentication enabled.',
      severity: 'high',
      provider: 'GCP',
      region: 'Global',
      icon: 'person_shield',
    },
    {
      id: 'DB-202',
      title: 'RDS Data Not Encrypted',
      description: "Database 'customer-db-v2' is not encrypted at rest using KMS service keys.",
      severity: 'critical',
      provider: 'AWS',
      region: 'ap-southeast-1',
      icon: 'database',
    },
  ];

  const auditStream = [
    { type: 'success', title: 'Policy Remediated', description: 'Admin resolved AWS-S3-01', time: '2 mins ago' },
    { type: 'sync', title: 'Azure Scan Complete', description: '12 new assets discovered', time: '15 mins ago' },
    { type: 'error', title: 'New Threat Flagged', description: 'Root MFA missing in GCP', time: '1 hour ago' },
  ];

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return { bg: 'bg-error/10', text: 'text-error', border: 'border-l-error' };
      case 'high':
        return { bg: 'bg-tertiary/10', text: 'text-tertiary', border: 'border-l-tertiary' };
      default:
        return { bg: 'bg-outline/10', text: 'text-outline', border: 'border-l-outline' };
    }
  };

  const getAuditIconColor = (type: string) => {
    switch (type) {
      case 'success':
        return 'bg-secondary/20 border-secondary/30 text-secondary';
      case 'sync':
        return 'bg-tertiary/20 border-tertiary/30 text-tertiary';
      case 'error':
        return 'bg-error/20 border-error/30 text-error';
      default:
        return 'bg-outline/20 border-outline/30 text-outline';
    }
  };

  // Button actions
  const handleFixNow = (id: string, title: string) => {
    setShowFixModal(id);
    showAlert('info', 'Remediation Review', `Reviewing options for ${title} (${id}).`);
  };

  const handleConfirmFix = () => {
    if (showFixModal) {
      showAlert('success', 'Remediation Started', `Successfully queued auto-remediation task for ${showFixModal}.`);
      setShowFixModal(null);
    }
  };

  const handleAssign = (id: string) => {
    showAlert('info', 'Case Assignment', `Assigned case ${id} to on-duty Security Operations analyst.`);
  };

  const handleExportAuditLog = () => {
    showAlert('success', 'Audit Export Started', 'Downloading system audit logs in CSV format.');
  };

  const handleNewScanFAB = () => {
    showAlert('info', 'Quick Scan', 'Triggering rapid vulnerability sweep across all cloud assets...');
    setTimeout(() => {
      showAlert('success', 'Scan Completed', 'Quick scan complete. Posture rating holds at 84%.');
    }, 3000);
  };

  const scrollFindings = (direction: 'left' | 'right') => {
    const container = findingsContainerRef.current;
    if (container) {
      const scrollAmt = direction === 'left' ? -340 : 340;
      container.scrollBy({ left: scrollAmt, behavior: 'smooth' });
    }
  };

  // Sample trend data for 30 days Area Chart
  const trendData = [
    { label: '30d ago', value: 72 },
    { label: '25d ago', value: 74 },
    { label: '20d ago', value: 73 },
    { label: '15d ago', value: 78 },
    { label: '10d ago', value: 80 },
    { label: '5d ago', value: 82 },
    { label: 'Current', value: 84 },
  ];

  const complianceData = [
    { label: '30d ago', value: 65 },
    { label: '25d ago', value: 68 },
    { label: '20d ago', value: 67 },
    { label: '15d ago', value: 72 },
    { label: '10d ago', value: 75 },
    { label: '5d ago', value: 74 },
    { label: 'Current', value: 76 },
  ];

  return (
    <main className="pt-16 pb-20 px-4 md:px-6 max-w-7xl mx-auto space-y-6">
      {/* Top Row: Score & Multi-Cloud Coverage */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-gutter">
        {/* Security Score Gauge */}
        <div className="lg:col-span-4 security-card rounded-xl p-6 flex flex-col items-center justify-center relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-secondary to-primary/50"></div>
          <h3 className="font-label-caps text-label-caps text-on-surface-variant mb-4 self-start">
            Overall Security Posture
          </h3>
          <div className="relative w-44 h-44 flex items-center justify-center">
            <DonutChart
              size={170}
              strokeWidth={12}
              centerLabel="/ 100"
              centerValue="84"
              data={[
                { label: 'Secure', value: 84, color: '#4edea3' },
                { label: 'Risks', value: 16, color: '#ffb4ab' },
              ]}
            />
          </div>
          <div className="mt-4 flex items-center gap-2 px-4 py-1 rounded-full bg-secondary/10 border border-secondary/20">
            <span className="w-2 h-2 rounded-full bg-secondary animate-pulse"></span>
            <span className="font-label-caps text-label-caps text-secondary uppercase tracking-widest">
              Status: Good
            </span>
          </div>
        </div>

        {/* Multi-Cloud Summary */}
        <div className="lg:col-span-8 security-card rounded-xl p-6">
          <div className="flex justify-between items-center mb-6">
            <h3 className="font-label-caps text-label-caps text-on-surface-variant">
              Cloud Infrastructure Coverage
            </h3>
            <span className="font-body-sm text-body-sm text-primary cursor-pointer hover:underline">
              Global Overview
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* AWS */}
            <div className="p-4 rounded-lg bg-surface-container-low border border-outline-variant/10">
              <div className="flex items-center justify-between mb-4">
                <div className="w-10 h-10 rounded bg-white/5 flex items-center justify-center">
                  <span className="material-symbols-outlined text-orange-400">cloud</span>
                </div>
                <span className="font-label-caps text-label-caps text-secondary px-2 py-0.5 rounded bg-secondary/10 border border-secondary/20">
                  Healthy
                </span>
              </div>
              <div className="font-headline-sm text-headline-sm mb-1">Amazon Web Services</div>
              <div className="font-mono-data text-mono-data text-on-surface-variant flex justify-between items-center">
                <span>1,242 Resources</span>
                <Sparkline data={[90, 91, 93, 92, 94, 92, 95]} color="#4edea3" />
              </div>
              <div className="mt-4 h-1 w-full bg-surface-container-highest rounded-full overflow-hidden">
                <div className="h-full bg-secondary w-[92%]"></div>
              </div>
            </div>
            {/* Azure */}
            <div className="p-4 rounded-lg bg-surface-container-low border border-outline-variant/10">
              <div className="flex items-center justify-between mb-4">
                <div className="w-10 h-10 rounded bg-white/5 flex items-center justify-center">
                  <span className="material-symbols-outlined text-blue-400">grid_view</span>
                </div>
                <span className="font-label-caps text-label-caps text-tertiary px-2 py-0.5 rounded bg-tertiary/10 border border-tertiary/20">
                  Review
                </span>
              </div>
              <div className="font-headline-sm text-headline-sm mb-1">Microsoft Azure</div>
              <div className="font-mono-data text-mono-data text-on-surface-variant flex justify-between items-center">
                <span>856 Resources</span>
                <Sparkline data={[70, 71, 74, 72, 73, 75, 74]} color="#ffb95f" />
              </div>
              <div className="mt-4 h-1 w-full bg-surface-container-highest rounded-full overflow-hidden">
                <div className="h-full bg-tertiary w-[74%]"></div>
              </div>
            </div>
            {/* GCP */}
            <div className="p-4 rounded-lg bg-surface-container-low border border-outline-variant/10">
              <div className="flex items-center justify-between mb-4">
                <div className="w-10 h-10 rounded bg-white/5 flex items-center justify-center">
                  <span className="material-symbols-outlined text-red-400">api</span>
                </div>
                <span className="font-label-caps text-label-caps text-error px-2 py-0.5 rounded bg-error/10 border border-error/20">
                  At Risk
                </span>
              </div>
              <div className="font-headline-sm text-headline-sm mb-1">Google Cloud Platform</div>
              <div className="font-mono-data text-mono-data text-on-surface-variant flex justify-between items-center">
                <span>412 Resources</span>
                <Sparkline data={[50, 48, 45, 47, 46, 44, 45]} color="#ffb4ab" />
              </div>
              <div className="mt-4 h-1 w-full bg-surface-container-highest rounded-full overflow-hidden">
                <div className="h-full bg-error w-[45%]"></div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Critical Findings Section */}
      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span
              className="material-symbols-outlined text-error"
              style={{ fontVariationSettings: "'FILL' 1" }}
            >
              warning
            </span>
            <h3 className="font-headline-sm text-headline-sm">Active Critical Findings</h3>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => scrollFindings('left')}
              className="p-1.5 rounded-full hover:bg-surface-variant/50 transition-colors border border-outline-variant/20"
            >
              <span className="material-symbols-outlined text-sm">chevron_left</span>
            </button>
            <button
              onClick={() => scrollFindings('right')}
              className="p-1.5 rounded-full hover:bg-surface-variant/50 transition-colors border border-outline-variant/20"
            >
              <span className="material-symbols-outlined text-sm">chevron_right</span>
            </button>
          </div>
        </div>
        <div
          ref={findingsContainerRef}
          className="flex overflow-x-auto gap-4 custom-scrollbar pb-4 -mx-1 px-1"
        >
          {criticalFindings.map((finding) => {
            const colors = getSeverityColor(finding.severity);
            return (
              <div
                key={finding.id}
                className={`min-w-[320px] max-w-[340px] flex-shrink-0 security-card rounded-xl p-4 border-l-4 ${colors.border}`}
              >
                <div className="flex justify-between items-start mb-4">
                  <span
                    className={`font-label-caps text-[10px] uppercase tracking-wider ${colors.bg} ${colors.text} px-2.5 py-0.5 rounded`}
                  >
                    {finding.severity}
                  </span>
                  <span className="font-mono-data text-xs text-on-surface-variant">
                    ID: {finding.id}
                  </span>
                </div>
                <div className="font-headline-sm text-[16px] mb-2">{finding.title}</div>
                <p className="font-body-sm text-[12px] text-on-surface-variant mb-4 h-10 overflow-hidden leading-relaxed">
                  {finding.description}
                </p>
                <div className="flex items-center justify-between mt-auto">
                  <div className="flex items-center gap-2">
                    <div className="w-6 h-6 rounded-full bg-white/10 flex items-center justify-center">
                      <span className="material-symbols-outlined text-xs">{finding.icon}</span>
                    </div>
                    <span className="font-body-sm text-xs text-on-surface-variant">
                      {finding.provider} / {finding.region}
                    </span>
                  </div>
                  <div className="flex gap-2">
                    <button
                      onClick={() => handleAssign(finding.id)}
                      className="px-2.5 py-1 rounded text-xs font-bold border border-outline-variant/20 hover:bg-surface-variant transition-all text-on-surface"
                    >
                      ASSIGN
                    </button>
                    <button
                      onClick={() => handleFixNow(finding.id, finding.title)}
                      className="px-2.5 py-1 rounded text-xs font-bold bg-error-container text-on-error-container hover:brightness-110 transition-all"
                    >
                      FIX NOW
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* Bottom Row: Chart & Audit Stream */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-gutter">
        {/* Security Posture Chart */}
        <div className="lg:col-span-8 security-card rounded-xl p-6">
          <div className="flex justify-between items-center mb-8">
            <h3 className="font-label-caps text-label-caps text-on-surface-variant">
              Security Posture & Compliance Trend
            </h3>
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-secondary"></span>
                <span className="font-label-caps text-label-caps text-on-surface-variant">Compliance</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-primary"></span>
                <span className="font-label-caps text-label-caps text-on-surface-variant">Score</span>
              </div>
            </div>
          </div>
          <AreaChart data={trendData} data2={complianceData} height={220} />
        </div>

        {/* Audit Stream */}
        <div className="lg:col-span-4 security-card rounded-xl p-6 flex flex-col justify-between">
          <div>
            <h3 className="font-label-caps text-label-caps text-on-surface-variant mb-4">Audit Stream</h3>
            <div className="space-y-4 max-h-[220px] overflow-y-auto pr-1 custom-scrollbar">
              {auditStream.map((item, index) => (
                <div key={index} className="flex gap-3 text-xs">
                  <div className="relative">
                    <div
                      className={`w-7 h-7 rounded-full flex items-center justify-center border ${getAuditIconColor(item.type)}`}
                    >
                      <span className="material-symbols-outlined text-xs">
                        {item.type === 'success' ? 'check' : item.type === 'sync' ? 'sync' : 'priority_high'}
                      </span>
                    </div>
                    {index < auditStream.length - 1 && (
                      <div className="absolute top-7 left-3.5 w-[1px] h-4 bg-outline-variant/30"></div>
                    )}
                  </div>
                  <div>
                    <div className="font-bold text-on-surface">{item.title}</div>
                    <div className="text-on-surface-variant mt-0.5">{item.description}</div>
                    <div className="font-mono-data text-[10px] text-outline mt-1">{item.time}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
          <button
            onClick={handleExportAuditLog}
            className="mt-6 w-full py-2.5 bg-surface-container-highest border border-outline-variant/20 rounded font-label-caps text-label-caps hover:bg-outline-variant transition-colors"
          >
            EXPORT AUDIT LOG
          </button>
        </div>
      </div>

      {/* FAB */}
      <button
        onClick={handleNewScanFAB}
        className="fixed right-6 bottom-20 md:bottom-10 w-14 h-14 bg-primary text-on-primary rounded-full flex items-center justify-center shadow-2xl hover:scale-110 transition-transform active:scale-95 z-40"
      >
        <span className="material-symbols-outlined text-3xl">add</span>
      </button>

      {/* Confirmation Modal */}
      {showFixModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-[99] flex items-center justify-center p-4">
          <div className="bg-surface-container-high border border-outline-variant/30 rounded-2xl max-w-md w-full p-6 space-y-4">
            <div className="flex items-center gap-3 text-error">
              <span className="material-symbols-outlined text-3xl">security</span>
              <h3 className="font-bold text-lg text-on-surface">Confirm Auto-Remediation</h3>
            </div>
            <p className="text-body-md text-on-surface-variant leading-relaxed">
              You are about to launch auto-remediation for <b>{showFixModal}</b>. This will request API configuration changes on your remote cloud account to enforce encryption or access limitations.
            </p>
            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={() => setShowFixModal(null)}
                className="px-4 py-2 border border-outline-variant/20 rounded-lg hover:bg-surface-variant transition-colors text-xs font-bold text-on-surface"
              >
                CANCEL
              </button>
              <button
                onClick={handleConfirmFix}
                className="px-4 py-2 bg-primary text-on-primary rounded-lg hover:brightness-110 transition-colors text-xs font-bold"
              >
                EXECUTE FIX
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Atmospheric Effect */}
      <div className="fixed inset-0 pointer-events-none -z-10 opacity-30 overflow-hidden">
        <div className="absolute -top-[10%] -left-[10%] w-[40%] h-[40%] bg-primary/20 rounded-full blur-[120px]"></div>
        <div className="absolute top-[40%] -right-[10%] w-[30%] h-[30%] bg-secondary/10 rounded-full blur-[100px]"></div>
      </div>
    </main>
  );
};

export default OverviewPage;
