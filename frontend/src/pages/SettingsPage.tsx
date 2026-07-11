import { useState } from 'react';
import { useAlert } from '../components/AlertProvider';

interface SettingSection {
  id: string;
  icon: string;
  label: string;
  accent: string;
  accentBg: string;
  accentBorder: string;
}

const sections: SettingSection[] = [
  { id: 'profile', icon: 'person', label: 'Profile', accent: 'text-cyan-400', accentBg: 'bg-cyan-500/10', accentBorder: 'border-cyan-500/30' },
  { id: 'cloud', icon: 'cloud', label: 'Cloud Accounts', accent: 'text-orange-400', accentBg: 'bg-orange-500/10', accentBorder: 'border-orange-500/30' },
  { id: 'security', icon: 'shield', label: 'Security', accent: 'text-red-400', accentBg: 'bg-red-500/10', accentBorder: 'border-red-500/30' },
  { id: 'notifications', icon: 'notifications', label: 'Notifications', accent: 'text-emerald-400', accentBg: 'bg-emerald-500/10', accentBorder: 'border-emerald-500/30' },
  { id: 'appearance', icon: 'palette', label: 'Appearance', accent: 'text-purple-400', accentBg: 'bg-purple-500/10', accentBorder: 'border-purple-500/30' },
];

const SettingsPage = () => {
  const { showAlert } = useAlert();
  const [activeSection, setActiveSection] = useState('profile');
  const [profile, setProfile] = useState({ name: 'Admin User', email: 'admin@sentinel-cspm.io', role: 'admin' });
  const [passwords, setPasswords] = useState({ current: '', new_pw: '', confirm: '' });
  const [notifPrefs, setNotifPrefs] = useState({
    critical: true, high: true, medium: true, low: false,
    email: true, slack: false, webhook: false,
  });
  const [theme, setTheme] = useState('cyber-blue');
  const [apiKey, setApiKey] = useState<string | null>(null);
  const [cloudAccounts] = useState([
    { id: '1', name: 'AWS Production', provider: 'aws', region: 'us-east-1', status: 'valid' },
    { id: '2', name: 'Azure Staging', provider: 'azure', region: 'West Europe', status: 'valid' },
    { id: '3', name: 'GCP Data Platform', provider: 'gcp', region: 'us-central1', status: 'invalid' },
  ]);

  const handleSaveProfile = () => {
    showAlert('success', 'Profile Updated', `Profile for ${profile.name} has been saved successfully.`);
  };

  const handleChangePassword = () => {
    if (passwords.new_pw !== passwords.confirm) {
      showAlert('error', 'Password Mismatch', 'New password and confirmation do not match.');
      return;
    }
    if (passwords.new_pw.length < 8) {
      showAlert('warning', 'Weak Password', 'Password must be at least 8 characters long.');
      return;
    }
    showAlert('success', 'Password Changed', 'Your password has been updated successfully.');
    setPasswords({ current: '', new_pw: '', confirm: '' });
  };

  const handleGenerateApiKey = () => {
    const key = 'cspm_' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    setApiKey(key);
    showAlert('success', 'API Key Generated', 'New API key has been created. Copy it now — it won\'t be shown again.');
  };

  const handleRevokeApiKey = () => {
    setApiKey(null);
    showAlert('warning', 'API Key Revoked', 'Your API key has been permanently revoked.');
  };

  const handleValidateAccount = (name: string) => {
    showAlert('info', 'Validating Credentials', `Testing connection to ${name}...`);
    setTimeout(() => {
      showAlert('success', 'Credentials Valid', `Successfully connected to ${name}.`);
    }, 2000);
  };

  const handleDeleteAccount = (name: string) => {
    showAlert('error', 'Account Removed', `Cloud account "${name}" has been disconnected.`);
  };

  const themeOptions = [
    { id: 'cyber-blue', label: 'Cyber Blue', primary: '#aac7ff', secondary: '#4edea3', preview: 'from-blue-600 to-cyan-500' },
    { id: 'neon-green', label: 'Neon Matrix', primary: '#4edea3', secondary: '#aac7ff', preview: 'from-emerald-600 to-green-400' },
    { id: 'solar-amber', label: 'Solar Amber', primary: '#ffb95f', secondary: '#ff8a65', preview: 'from-amber-600 to-orange-400' },
    { id: 'plasma-magenta', label: 'Plasma Magenta', primary: '#e879f9', secondary: '#c084fc', preview: 'from-fuchsia-600 to-purple-400' },
  ];

  const inputCls = 'w-full bg-surface-container-lowest border border-outline-variant/20 rounded-lg px-4 py-2.5 text-body-md text-on-surface focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary/30 transition-all';
  const btnPrimary = 'px-5 py-2.5 bg-primary text-on-primary rounded-lg font-bold text-sm hover:brightness-110 transition-all active:scale-95';
  const btnDanger = 'px-5 py-2.5 bg-error-container text-on-error-container rounded-lg font-bold text-sm hover:brightness-110 transition-all active:scale-95';

  const renderSection = () => {
    const sec = sections.find(s => s.id === activeSection)!;
    switch (activeSection) {
      case 'profile':
        return (
          <div className="space-y-6">
            <div className="flex items-center gap-4 mb-8">
              <div className={`w-16 h-16 rounded-2xl ${sec.accentBg} border ${sec.accentBorder} flex items-center justify-center`}>
                <span className={`material-symbols-outlined text-3xl ${sec.accent}`} style={{ fontVariationSettings: "'FILL' 1" }}>account_circle</span>
              </div>
              <div>
                <h3 className="text-lg font-bold text-on-surface">{profile.name}</h3>
                <span className={`text-xs font-mono uppercase tracking-widest ${sec.accent}`}>{profile.role}</span>
              </div>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs text-on-surface-variant uppercase tracking-wider mb-2">Full Name</label>
                <input className={inputCls} value={profile.name} onChange={e => setProfile({ ...profile, name: e.target.value })} />
              </div>
              <div>
                <label className="block text-xs text-on-surface-variant uppercase tracking-wider mb-2">Email Address</label>
                <input className={inputCls} value={profile.email} onChange={e => setProfile({ ...profile, email: e.target.value })} />
              </div>
            </div>
            <button className={btnPrimary} onClick={handleSaveProfile}>
              <span className="flex items-center gap-2">
                <span className="material-symbols-outlined text-sm">save</span> Save Changes
              </span>
            </button>
          </div>
        );

      case 'cloud':
        return (
          <div className="space-y-4">
            <div className="flex items-center justify-between mb-6">
              <p className="text-sm text-on-surface-variant">Manage your connected cloud provider accounts.</p>
              <button className={btnPrimary} onClick={() => showAlert('info', 'Add Account', 'Cloud account wizard would open here.')}>
                <span className="flex items-center gap-2">
                  <span className="material-symbols-outlined text-sm">add</span> Add Account
                </span>
              </button>
            </div>
            {cloudAccounts.map(acc => (
              <div key={acc.id} className={`p-4 rounded-xl ${sec.accentBg} border ${sec.accentBorder} flex items-center justify-between group hover:border-orange-400/50 transition-all`}>
                <div className="flex items-center gap-4">
                  <div className="w-10 h-10 rounded-lg bg-surface-container-highest flex items-center justify-center">
                    <span className={`material-symbols-outlined ${acc.provider === 'aws' ? 'text-orange-400' : acc.provider === 'azure' ? 'text-blue-400' : 'text-red-400'}`}>
                      {acc.provider === 'aws' ? 'cloud' : acc.provider === 'azure' ? 'grid_view' : 'api'}
                    </span>
                  </div>
                  <div>
                    <div className="font-bold text-sm text-on-surface">{acc.name}</div>
                    <div className="text-xs text-on-surface-variant font-mono">{acc.provider.toUpperCase()} • {acc.region}</div>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <span className={`text-xs font-bold uppercase tracking-wider px-2 py-1 rounded-full ${acc.status === 'valid' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-red-500/10 text-red-400 border border-red-500/20'}`}>
                    {acc.status === 'valid' ? '● Connected' : '● Invalid'}
                  </span>
                  <button onClick={() => handleValidateAccount(acc.name)} className="p-2 rounded-lg hover:bg-surface-container-highest transition-colors opacity-0 group-hover:opacity-100">
                    <span className="material-symbols-outlined text-sm text-on-surface-variant">refresh</span>
                  </button>
                  <button onClick={() => handleDeleteAccount(acc.name)} className="p-2 rounded-lg hover:bg-red-500/10 transition-colors opacity-0 group-hover:opacity-100">
                    <span className="material-symbols-outlined text-sm text-red-400">delete</span>
                  </button>
                </div>
              </div>
            ))}
          </div>
        );

      case 'security':
        return (
          <div className="space-y-8">
            <div>
              <h4 className="text-sm font-bold text-on-surface mb-4 flex items-center gap-2">
                <span className={`material-symbols-outlined ${sec.accent}`}>lock</span> Change Password
              </h4>
              <div className="space-y-3 max-w-md">
                <input type="password" className={inputCls} placeholder="Current Password" value={passwords.current} onChange={e => setPasswords({ ...passwords, current: e.target.value })} />
                <input type="password" className={inputCls} placeholder="New Password" value={passwords.new_pw} onChange={e => setPasswords({ ...passwords, new_pw: e.target.value })} />
                <input type="password" className={inputCls} placeholder="Confirm New Password" value={passwords.confirm} onChange={e => setPasswords({ ...passwords, confirm: e.target.value })} />
                <button className={btnPrimary} onClick={handleChangePassword}>Update Password</button>
              </div>
            </div>
            <div className="border-t border-outline-variant/20 pt-6">
              <h4 className="text-sm font-bold text-on-surface mb-4 flex items-center gap-2">
                <span className={`material-symbols-outlined ${sec.accent}`}>key</span> API Key Management
              </h4>
              {apiKey ? (
                <div className="space-y-3">
                  <div className="p-3 bg-surface-container-lowest rounded-lg border border-outline-variant/20 font-mono text-xs text-on-surface break-all">{apiKey}</div>
                  <div className="flex gap-3">
                    <button className={btnPrimary} onClick={() => { navigator.clipboard.writeText(apiKey); showAlert('success', 'Copied', 'API key copied to clipboard.'); }}>
                      <span className="flex items-center gap-2"><span className="material-symbols-outlined text-sm">content_copy</span> Copy</span>
                    </button>
                    <button className={btnDanger} onClick={handleRevokeApiKey}>Revoke Key</button>
                  </div>
                </div>
              ) : (
                <button className={btnPrimary} onClick={handleGenerateApiKey}>
                  <span className="flex items-center gap-2"><span className="material-symbols-outlined text-sm">vpn_key</span> Generate API Key</span>
                </button>
              )}
            </div>
          </div>
        );

      case 'notifications':
        return (
          <div className="space-y-6">
            <div>
              <h4 className="text-sm font-bold text-on-surface mb-4">Alert Severity Filters</h4>
              <div className="space-y-3">
                {(['critical', 'high', 'medium', 'low'] as const).map(sev => {
                  const colors: Record<string, string> = { critical: 'bg-red-500', high: 'bg-amber-500', medium: 'bg-blue-400', low: 'bg-emerald-400' };
                  const key = sev as keyof typeof notifPrefs;
                  return (
                    <label key={sev} className={`flex items-center justify-between p-3 rounded-xl ${sec.accentBg} border ${sec.accentBorder} cursor-pointer hover:border-emerald-400/50 transition-all`}>
                      <div className="flex items-center gap-3">
                        <span className={`w-3 h-3 rounded-full ${colors[sev]}`} />
                        <span className="text-sm text-on-surface capitalize font-medium">{sev} Alerts</span>
                      </div>
                      <div className="relative">
                        <input type="checkbox" checked={notifPrefs[key] as boolean} onChange={() => { setNotifPrefs(p => ({ ...p, [key]: !p[key] })); showAlert('info', 'Preference Updated', `${sev} alerts ${!notifPrefs[key] ? 'enabled' : 'disabled'}.`); }} className="sr-only peer" />
                        <div className="w-11 h-6 bg-surface-container-highest rounded-full peer-checked:bg-emerald-500/60 transition-colors" />
                        <div className="absolute left-0.5 top-0.5 w-5 h-5 bg-on-surface rounded-full peer-checked:translate-x-5 transition-transform shadow-md" />
                      </div>
                    </label>
                  );
                })}
              </div>
            </div>
            <div className="border-t border-outline-variant/20 pt-6">
              <h4 className="text-sm font-bold text-on-surface mb-4">Delivery Channels</h4>
              <div className="space-y-3">
                {[
                  { key: 'email', label: 'Email Notifications', icon: 'email' },
                  { key: 'slack', label: 'Slack Integration', icon: 'chat' },
                  { key: 'webhook', label: 'Webhook Delivery', icon: 'webhook' },
                ].map(ch => (
                  <label key={ch.key} className={`flex items-center justify-between p-3 rounded-xl ${sec.accentBg} border ${sec.accentBorder} cursor-pointer hover:border-emerald-400/50 transition-all`}>
                    <div className="flex items-center gap-3">
                      <span className={`material-symbols-outlined text-sm ${sec.accent}`}>{ch.icon}</span>
                      <span className="text-sm text-on-surface font-medium">{ch.label}</span>
                    </div>
                    <div className="relative">
                      <input type="checkbox" checked={(notifPrefs as any)[ch.key]} onChange={() => { setNotifPrefs(p => ({ ...p, [ch.key]: !(p as any)[ch.key] })); showAlert('info', 'Channel Updated', `${ch.label} ${!(notifPrefs as any)[ch.key] ? 'enabled' : 'disabled'}.`); }} className="sr-only peer" />
                      <div className="w-11 h-6 bg-surface-container-highest rounded-full peer-checked:bg-emerald-500/60 transition-colors" />
                      <div className="absolute left-0.5 top-0.5 w-5 h-5 bg-on-surface rounded-full peer-checked:translate-x-5 transition-transform shadow-md" />
                    </div>
                  </label>
                ))}
              </div>
            </div>
          </div>
        );

      case 'appearance':
        return (
          <div className="space-y-6">
            <h4 className="text-sm font-bold text-on-surface mb-4">Color Theme</h4>
            <div className="grid grid-cols-2 gap-4">
              {themeOptions.map(t => (
                <button
                  key={t.id}
                  onClick={() => { setTheme(t.id); showAlert('success', 'Theme Applied', `Switched to ${t.label} theme.`); }}
                  className={`p-4 rounded-xl border transition-all ${theme === t.id ? `${sec.accentBorder} ${sec.accentBg} ring-2 ring-purple-400/30` : 'border-outline-variant/20 bg-surface-container-low hover:border-purple-400/30'}`}
                >
                  <div className={`w-full h-8 rounded-lg bg-gradient-to-r ${t.preview} mb-3`} />
                  <div className="text-sm font-bold text-on-surface">{t.label}</div>
                  <div className="flex items-center gap-2 mt-2">
                    <span className="w-3 h-3 rounded-full" style={{ backgroundColor: t.primary }} />
                    <span className="w-3 h-3 rounded-full" style={{ backgroundColor: t.secondary }} />
                  </div>
                </button>
              ))}
            </div>
            <div className="border-t border-outline-variant/20 pt-6">
              <h4 className="text-sm font-bold text-on-surface mb-4">Display Options</h4>
              <div className="space-y-3">
                {['Compact Mode', 'High Contrast', 'Reduced Motion'].map(opt => (
                  <label key={opt} className={`flex items-center justify-between p-3 rounded-xl ${sec.accentBg} border ${sec.accentBorder} cursor-pointer hover:border-purple-400/50 transition-all`}>
                    <span className="text-sm text-on-surface font-medium">{opt}</span>
                    <div className="relative">
                      <input type="checkbox" className="sr-only peer" onChange={() => showAlert('info', 'Display Updated', `${opt} toggled.`)} />
                      <div className="w-11 h-6 bg-surface-container-highest rounded-full peer-checked:bg-purple-500/60 transition-colors" />
                      <div className="absolute left-0.5 top-0.5 w-5 h-5 bg-on-surface rounded-full peer-checked:translate-x-5 transition-transform shadow-md" />
                    </div>
                  </label>
                ))}
              </div>
            </div>
          </div>
        );

      default:
        return null;
    }
  };

  const currentSection = sections.find(s => s.id === activeSection)!;

  return (
    <main className="pt-16 pb-20 px-4 md:px-6 max-w-5xl mx-auto">
      <div className="mb-8">
        <h1 className="font-headline-lg text-headline-lg text-on-surface">Settings</h1>
        <p className="text-body-md text-on-surface-variant mt-1">Configure your CSPM platform preferences.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
        {/* Section Nav */}
        <div className="md:col-span-3 space-y-1">
          {sections.map(sec => (
            <button
              key={sec.id}
              onClick={() => setActiveSection(sec.id)}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium transition-all ${
                activeSection === sec.id
                  ? `${sec.accentBg} ${sec.accent} border ${sec.accentBorder}`
                  : 'text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface'
              }`}
            >
              <span
                className="material-symbols-outlined text-lg"
                style={activeSection === sec.id ? { fontVariationSettings: "'FILL' 1" } : {}}
              >
                {sec.icon}
              </span>
              {sec.label}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="md:col-span-9">
          <div className={`security-card rounded-2xl p-6 md:p-8 border-t-4 ${currentSection.accentBorder.replace('/30', '')}`}>
            <div className="flex items-center gap-3 mb-6">
              <div className={`w-10 h-10 rounded-xl ${currentSection.accentBg} border ${currentSection.accentBorder} flex items-center justify-center`}>
                <span
                  className={`material-symbols-outlined ${currentSection.accent}`}
                  style={{ fontVariationSettings: "'FILL' 1" }}
                >
                  {currentSection.icon}
                </span>
              </div>
              <div>
                <h2 className="text-lg font-bold text-on-surface">{currentSection.label}</h2>
              </div>
            </div>
            {renderSection()}
          </div>
        </div>
      </div>
    </main>
  );
};

export default SettingsPage;
