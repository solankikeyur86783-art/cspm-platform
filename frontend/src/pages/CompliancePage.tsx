import { useState } from 'react';
import { DonutChart } from '../components/Charts';
import { useAlert } from '../components/AlertProvider';

const FRAMEWORKS = [
  { id: 'cis', name: 'CIS Benchmarks v8', score: 82, passing: 41, failing: 9, total: 50 },
  { id: 'soc2', name: 'SOC 2 Type II', score: 76, passing: 38, failing: 12, total: 50 },
  { id: 'hipaa', name: 'HIPAA Security Rule', score: 90, passing: 45, failing: 5, total: 50 },
  { id: 'pci-dss', name: 'PCI-DSS v4.0', score: 68, passing: 34, failing: 16, total: 50 },
];

const COMPLIANCE_CONTROLS = {
  cis: [
    { id: 'CIS-1.1', title: 'Avoid the use of the root account', status: 'passing', severity: 'critical', rules: ['IAM-001', 'IAM-002'] },
    { id: 'CIS-2.1', title: 'Ensure S3 Buckets are encrypted', status: 'passing', severity: 'high', rules: ['S3-001'] },
    { id: 'CIS-3.1', title: 'Ensure MFA is enabled for all users', status: 'failing', severity: 'critical', rules: ['IAM-003'] },
    { id: 'CIS-4.1', title: 'Ensure security groups restrict SSH access', status: 'failing', severity: 'high', rules: ['NET-001'] },
    { id: 'CIS-5.1', title: 'Ensure CloudTrail is enabled in all regions', status: 'passing', severity: 'medium', rules: ['LOG-001'] },
  ],
  soc2: [
    { id: 'CC6.1', title: 'Logical Access Controls (MFA / IAM)', status: 'failing', severity: 'critical', rules: ['IAM-003', 'IAM-012'] },
    { id: 'CC6.3', title: 'Perimeter Defense (Security Groups)', status: 'failing', severity: 'high', rules: ['NET-001', 'NET-004'] },
    { id: 'CC6.6', title: 'Data Transmission Encryption', status: 'passing', severity: 'high', rules: ['S3-002'] },
    { id: 'CC7.1', title: 'Vulnerability Management System', status: 'passing', severity: 'medium', rules: ['VUL-001'] },
  ],
  hipaa: [
    { id: '164.312(a)', title: 'Access Control (Unique User Identification)', status: 'passing', severity: 'high', rules: ['IAM-005'] },
    { id: '164.312(c)', title: 'Integrity (MFA & Audit Logs)', status: 'passing', severity: 'medium', rules: ['LOG-003'] },
    { id: '164.312(e)', title: 'Transmission Security (Data in Transit)', status: 'passing', severity: 'high', rules: ['NET-009'] },
  ],
  'pci-dss': [
    { id: 'PCI-1.2', title: 'Restrict inbound and outbound traffic', status: 'failing', severity: 'critical', rules: ['NET-001'] },
    { id: 'PCI-2.2', title: 'Apply secure configuration settings', status: 'failing', severity: 'high', rules: ['S3-001', 'DB-002'] },
    { id: 'PCI-8.3', title: 'Secure multi-factor authentication', status: 'passing', severity: 'critical', rules: ['IAM-003'] },
  ]
};

const CompliancePage = () => {
  const { showAlert } = useAlert();
  const [selectedFramework, setSelectedFramework] = useState('cis');

  const currentFramework = FRAMEWORKS.find((f) => f.id === selectedFramework) || FRAMEWORKS[0];
  const controls = (COMPLIANCE_CONTROLS as any)[selectedFramework] || [];

  const handleFixControl = (controlId: string, rules: string[]) => {
    showAlert('info', 'Remediating Control', `Executing remediation rules for ${controlId}...`);
    setTimeout(() => {
      showAlert('success', 'Control Remediated', `Successfully initiated remediation for ${controlId} (${rules.join(', ')}).`);
    }, 2000);
  };

  const handleExportFramework = (frameworkName: string) => {
    const controlsData = (COMPLIANCE_CONTROLS as any)[selectedFramework] || [];
    const fw = currentFramework;
    const date = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });

    const rows = controlsData.map((c: any) => `
      <tr style="border-bottom:1px solid #e5e7eb">
        <td style="padding:10px 12px;font-weight:600">${c.id}</td>
        <td style="padding:10px 12px">${c.title}</td>
        <td style="padding:10px 12px">
          <span style="padding:3px 10px;border-radius:9999px;font-size:12px;font-weight:700;
            background:${c.status === 'passing' ? '#dcfce7' : '#fee2e2'};
            color:${c.status === 'passing' ? '#166534' : '#991b1b'}">
            ${c.status.toUpperCase()}
          </span>
        </td>
        <td style="padding:10px 12px">
          <span style="padding:3px 10px;border-radius:9999px;font-size:12px;
            background:${c.severity === 'critical' ? '#fee2e2' : c.severity === 'high' ? '#ffedd5' : '#fef9c3'};
            color:${c.severity === 'critical' ? '#991b1b' : c.severity === 'high' ? '#9a3412' : '#854d0e'}">
            ${c.severity.toUpperCase()}
          </span>
        </td>
        <td style="padding:10px 12px;color:#6b7280;font-size:13px">${c.rules.join(', ')}</td>
      </tr>`).join('');

    const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>${frameworkName} — CSPM Compliance Report</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; color: #111; margin: 40px; }
    h1 { font-size: 24px; font-weight: 800; color: #1e40af; margin-bottom: 4px; }
    .meta { color: #6b7280; font-size: 13px; margin-bottom: 32px; }
    .score-bar { display: flex; gap: 24px; margin-bottom: 32px; }
    .score-box { background: #f1f5f9; border-radius: 12px; padding: 16px 24px; min-width: 120px; text-align: center; }
    .score-box .val { font-size: 36px; font-weight: 800; color: ${fw.score >= 80 ? '#16a34a' : fw.score >= 60 ? '#d97706' : '#dc2626'}; }
    .score-box .lbl { font-size: 12px; color: #6b7280; text-transform: uppercase; margin-top: 4px; }
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    thead { background: #1e40af; color: white; }
    thead th { padding: 10px 12px; text-align: left; }
    tr:nth-child(even) { background: #f8fafc; }
    @media print { body { margin: 20px; } }
  </style>
</head>
<body>
  <h1>🛡️ ${frameworkName} — Compliance Report</h1>
  <div class="meta">Generated by SENTINEL CSPM Platform &nbsp;|&nbsp; ${date}</div>
  <div class="score-bar">
    <div class="score-box"><div class="val">${fw.score}%</div><div class="lbl">Compliance Score</div></div>
    <div class="score-box"><div class="val" style="color:#16a34a">${fw.passing}</div><div class="lbl">Passing Controls</div></div>
    <div class="score-box"><div class="val" style="color:#dc2626">${fw.failing}</div><div class="lbl">Failing Controls</div></div>
    <div class="score-box"><div class="val">${fw.total}</div><div class="lbl">Total Controls</div></div>
  </div>
  <table>
    <thead><tr><th>Control ID</th><th>Title</th><th>Status</th><th>Severity</th><th>Rules</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
  <script>window.onload = () => { window.print(); }<\/script>
</body>
</html>`;

    const win = window.open('', '_blank');
    if (win) {
      win.document.write(html);
      win.document.close();
      showAlert('success', 'PDF Report Ready', `Opening print dialog for ${frameworkName} compliance report.`);
    } else {
      showAlert('error', 'Popup Blocked', 'Please allow popups for this site to export PDF.');
    }
  };

  return (
    <main className="pt-16 pb-20 px-4 md:px-6 max-w-7xl mx-auto space-y-6">
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
        <div>
          <h1 className="font-headline-lg text-headline-lg text-on-surface">Compliance Frameworks</h1>
          <p className="text-body-md text-on-surface-variant mt-1">
            Track and satisfy compliance controls across CIS, SOC 2, HIPAA, and PCI-DSS.
          </p>
        </div>
        <button
          onClick={() => handleExportFramework(currentFramework.name)}
          className="bg-primary text-on-primary hover:brightness-110 font-bold px-4 py-2 rounded-lg text-sm transition-all flex items-center gap-2"
        >
          <span className="material-symbols-outlined text-sm">download</span> Export PDF Report
        </button>
      </div>

      {/* Selector Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {FRAMEWORKS.map((f) => (
          <button
            key={f.id}
            onClick={() => {
              setSelectedFramework(f.id);
              showAlert('info', 'Framework Switched', `Now viewing compliance posture for ${f.name}.`);
            }}
            className={`p-4 rounded-xl border text-left transition-all ${
              selectedFramework === f.id
                ? 'border-primary bg-primary/10 shadow-lg'
                : 'border-outline-variant/20 bg-surface-container-low hover:border-primary/40'
            }`}
          >
            <div className="font-bold text-sm text-on-surface mb-2">{f.name}</div>
            <div className="flex items-end justify-between">
              <div>
                <span className="text-2xl font-bold text-primary">{f.score}%</span>
                <span className="text-[10px] text-on-surface-variant block mt-1 uppercase tracking-wider">
                  {f.passing} / {f.total} Controls
                </span>
              </div>
              <span className={`material-symbols-outlined ${f.score >= 80 ? 'text-secondary' : 'text-tertiary'}`}>
                {f.score >= 80 ? 'verified_user' : 'gpp_maybe'}
              </span>
            </div>
          </button>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Posture Overview */}
        <div className="lg:col-span-4 security-card rounded-xl p-6 flex flex-col items-center justify-center text-center">
          <h3 className="font-label-caps text-label-caps text-on-surface-variant mb-6 self-start">
            {currentFramework.name} Overview
          </h3>
          <DonutChart
            size={180}
            strokeWidth={16}
            centerLabel="Score"
            centerValue={`${currentFramework.score}%`}
            data={[
              { label: 'Passing', value: currentFramework.passing, color: '#4edea3' },
              { label: 'Failing', value: currentFramework.failing, color: '#ffb4ab' },
            ]}
          />
          <div className="grid grid-cols-2 gap-4 w-full mt-6 text-left">
            <div className="p-3 bg-surface-container-low rounded-lg border border-outline-variant/10">
              <span className="text-[10px] text-on-surface-variant uppercase tracking-wider block">Passing</span>
              <span className="text-lg font-bold text-secondary">{currentFramework.passing} Controls</span>
            </div>
            <div className="p-3 bg-surface-container-low rounded-lg border border-outline-variant/10">
              <span className="text-[10px] text-on-surface-variant uppercase tracking-wider block">Failing</span>
              <span className="text-lg font-bold text-error">{currentFramework.failing} Controls</span>
            </div>
          </div>
        </div>

        {/* Controls Table */}
        <div className="lg:col-span-8 security-card rounded-xl overflow-hidden flex flex-col">
          <div className="p-4 border-b border-outline-variant/20 bg-surface-container flex items-center justify-between">
            <h3 className="font-label-caps text-label-caps text-on-surface-variant">Control Requirements</h3>
            <span className="text-xs text-on-surface-variant font-mono">Total {controls.length} checks</span>
          </div>
          <div className="overflow-x-auto flex-1">
            <table className="w-full text-left border-collapse min-w-[600px]">
              <thead>
                <tr className="bg-surface-container-high border-b border-outline-variant/20">
                  <th className="px-4 py-3 font-label-caps text-label-caps text-on-surface-variant">ID / Name</th>
                  <th className="px-4 py-3 font-label-caps text-label-caps text-on-surface-variant">Severity</th>
                  <th className="px-4 py-3 font-label-caps text-label-caps text-on-surface-variant">Associated Rules</th>
                  <th className="px-4 py-3 font-label-caps text-label-caps text-on-surface-variant">State</th>
                  <th className="px-4 py-3 font-label-caps text-label-caps text-on-surface-variant text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-outline-variant/10">
                {controls.map((control: any) => (
                  <tr key={control.id} className="hover:bg-primary/5 transition-colors">
                    <td className="px-4 py-3">
                      <div className="font-bold text-sm">{control.id}</div>
                      <div className="text-xs text-on-surface-variant truncate max-w-[280px]">{control.title}</div>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded ${
                        control.severity === 'critical' ? 'bg-error/10 text-error' : control.severity === 'high' ? 'bg-tertiary/10 text-tertiary' : 'bg-primary/10 text-primary'
                      }`}>
                        {control.severity}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-on-surface-variant">
                      {control.rules.join(', ')}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`flex items-center gap-1.5 text-xs font-bold ${
                        control.status === 'passing' ? 'text-secondary' : 'text-error'
                      }`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${control.status === 'passing' ? 'bg-secondary' : 'bg-error'}`} />
                        {control.status.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right">
                      {control.status === 'failing' ? (
                        <button
                          onClick={() => handleFixControl(control.id, control.rules)}
                          className="bg-error-container text-on-error-container hover:brightness-110 font-bold px-3 py-1 rounded text-xs transition-all"
                        >
                          FIX NOW
                        </button>
                      ) : (
                        <button
                          disabled
                          className="text-on-surface-variant/40 border border-outline-variant/10 px-3 py-1 rounded text-xs"
                        >
                          VERIFIED
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </main>
  );
};

export default CompliancePage;
