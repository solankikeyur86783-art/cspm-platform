import { useState } from 'react';
import { useAlert } from './AlertProvider';

interface HeaderProps {
  currentPage: string;
  onNavigate: (page: string) => void;
  onLogout?: () => void;
}

const Header = ({ currentPage, onNavigate, onLogout }: HeaderProps) => {
  const { showAlert } = useAlert();
  const [showNotifications, setShowNotifications] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [unreadNotifications, setUnreadNotifications] = useState([
    { id: '1', text: 'Critical vulnerability detected: S3 Bucket Publicly Accessible', type: 'error' },
    { id: '2', text: 'Auto remediation success: EBS Volume Encrypted', type: 'success' },
    { id: '3', text: 'Compliance check complete: SOC2 Framework 78%', type: 'info' }
  ]);

  const handleSearch = () => {
    showAlert('info', 'Command Center', 'Interactive search capability initiated. Type queries directly.');
  };

  const handleNotificationClick = (id: string, text: string) => {
    showAlert('info', 'Notification Details', text);
    setUnreadNotifications(prev => prev.filter(n => n.id !== id));
  };

  const handleClearNotifications = () => {
    setUnreadNotifications([]);
    showAlert('success', 'Notifications Cleared', 'All unread notifications marked as read.');
    setShowNotifications(false);
  };

  const handleUserAction = (page: string) => {
    onNavigate(page);
    setShowUserMenu(false);
    showAlert('info', 'Navigation', `Opened user ${page} section.`);
  };

  return (
    <header className="fixed top-0 left-0 w-full z-50 flex justify-between items-center px-4 h-14 bg-surface-container-highest border-b border-outline-variant/10">
      <div className="flex items-center gap-3 cursor-pointer" onClick={() => onNavigate('overview')}>
        <span className="material-symbols-outlined text-primary text-2xl" style={{ fontVariationSettings: "'FILL' 1" }}>
          security
        </span>
        <span className="font-headline-sm text-headline-sm font-bold tracking-tight text-primary">
          SENTINEL CSPM
        </span>
      </div>

      <nav className="hidden md:flex items-center gap-6">
        {[
          { page: 'overview', label: 'Overview' },
          { page: 'compliance', label: 'Compliance' },
          { page: 'threats', label: 'Threats' },
          { page: 'assets', label: 'Assets' },
          { page: 'logs', label: 'Logs' }
        ].map((item) => (
          <button
            key={item.page}
            onClick={() => onNavigate(item.page)}
            className={`font-label-caps text-label-caps px-2 transition-colors ${
              currentPage === item.page
                ? 'text-primary border-b-2 border-primary py-1'
                : 'text-on-surface-variant hover:text-on-surface'
            }`}
          >
            {item.label}
          </button>
        ))}
      </nav>

      <div className="flex items-center gap-4 relative">
        <span
          onClick={handleSearch}
          className="material-symbols-outlined text-on-surface-variant cursor-pointer hover:text-primary transition-colors"
        >
          search
        </span>

        {/* Notifications Icon & Dropdown */}
        <div className="relative">
          <span
            onClick={() => { setShowNotifications(!showNotifications); setShowUserMenu(false); }}
            className="material-symbols-outlined text-on-surface-variant cursor-pointer hover:text-primary transition-colors relative"
          >
            notifications
            {unreadNotifications.length > 0 && (
              <span className="absolute top-0 right-0 w-2.5 h-2.5 bg-error rounded-full animate-pulse"></span>
            )}
          </span>

          {showNotifications && (
            <div className="absolute right-0 mt-3 w-80 bg-surface-container-high border border-outline-variant/30 rounded-xl shadow-2xl z-50 overflow-hidden">
              <div className="p-3 border-b border-outline-variant/20 flex justify-between items-center bg-surface-container-highest">
                <span className="font-bold text-xs uppercase text-on-surface-variant">Alert Feed</span>
                {unreadNotifications.length > 0 && (
                  <button onClick={handleClearNotifications} className="text-[10px] text-primary hover:underline font-bold">
                    Clear All
                  </button>
                )}
              </div>
              <div className="max-h-60 overflow-y-auto divide-y divide-outline-variant/10">
                {unreadNotifications.length > 0 ? (
                  unreadNotifications.map(n => (
                    <div
                      key={n.id}
                      onClick={() => handleNotificationClick(n.id, n.text)}
                      className="p-3 hover:bg-surface-variant/40 cursor-pointer transition-colors text-xs text-on-surface"
                    >
                      <div className="flex items-start gap-2">
                        <span className={`w-1.5 h-1.5 rounded-full mt-1.5 ${n.type === 'error' ? 'bg-error' : n.type === 'success' ? 'bg-secondary' : 'bg-primary'}`} />
                        <span className="flex-1">{n.text}</span>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="p-4 text-center text-xs text-on-surface-variant">
                    No new alerts to show.
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* User Account Menu Dropdown */}
        <div className="relative">
          <span
            onClick={() => { setShowUserMenu(!showUserMenu); setShowNotifications(false); }}
            className="material-symbols-outlined text-primary text-2xl cursor-pointer hover:scale-105 transition-transform"
            style={{ fontVariationSettings: "'FILL' 1" }}
          >
            account_circle
          </span>

          {showUserMenu && (
            <div className="absolute right-0 mt-3 w-48 bg-surface-container-high border border-outline-variant/30 rounded-xl shadow-2xl z-50 overflow-hidden">
              <div className="p-3 border-b border-outline-variant/20 bg-surface-container-highest text-xs text-on-surface-variant">
                Signed in as <b className="text-on-surface block">admin@sentinel.io</b>
              </div>
              <div className="flex flex-col py-1">
                <button
                  onClick={() => handleUserAction('settings')}
                  className="px-4 py-2 text-left text-xs hover:bg-surface-variant/50 text-on-surface transition-colors flex items-center gap-2"
                >
                  <span className="material-symbols-outlined text-sm">settings</span> Settings
                </button>
                <button
                  onClick={() => handleUserAction('compliance')}
                  className="px-4 py-2 text-left text-xs hover:bg-surface-variant/50 text-on-surface transition-colors flex items-center gap-2"
                >
                  <span className="material-symbols-outlined text-sm">verified_user</span> Compliance
                </button>
                <div className="border-t border-outline-variant/15 my-1" />
                <button
                  onClick={() => {
                    setShowUserMenu(false);
                    showAlert('warning', 'Sign Out', 'Signing out of SENTINEL CSPM...');
                    setTimeout(() => onLogout?.(), 800);
                  }}
                  className="px-4 py-2 text-left text-xs hover:bg-red-500/10 text-error transition-colors flex items-center gap-2"
                >
                  <span className="material-symbols-outlined text-sm">logout</span> Sign Out
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};

export default Header;
