import { useAlert } from './AlertProvider';

interface SidebarProps {
  currentPage: string;
  onNavigate: (page: string) => void;
  visible?: boolean;
}

const Sidebar = ({ currentPage, onNavigate, visible = true }: SidebarProps) => {
  const { showAlert } = useAlert();

  if (!visible) return null;

  const menuItems = [
    { id: 'overview', icon: 'dashboard', label: 'Overview' },
    { id: 'compliance', icon: 'verified_user', label: 'Compliance' },
    { id: 'inventory', icon: 'inventory_2', label: 'Inventory' },
    { id: 'vulnerabilities', icon: 'gpp_maybe', label: 'Vulnerabilities' },
    { id: 'logs', icon: 'receipt_long', label: 'Logs' },
    { id: 'settings', icon: 'settings', label: 'Settings' },
  ];

  const bottomItems = [
    { id: 'support', icon: 'contact_support', label: 'Support' },
    { id: 'docs', icon: 'menu_book', label: 'Documentation' },
  ];

  const handleNewScan = () => {
    showAlert('info', 'Scan Queued', 'Triggered full infrastructure security scan in the background.');
    setTimeout(() => {
      showAlert('success', 'Scan Completed', 'Discovered 14,284 resources, 42 vulnerabilities flagged.');
    }, 4000);
  };

  const handleBottomItem = (_id: string, label: string) => {
    showAlert('info', label, `Redirecting to Sentinel CSPM ${label.toLowerCase()} center...`);
  };

  return (
    <aside className="hidden md:flex flex-col py-md z-40 bg-surface-container fixed top-14 left-0 bottom-0 w-60 border-r border-outline-variant shadow-sm">
      <div className="px-md mb-xl">
        <div className="flex items-center gap-sm px-sm py-xs bg-surface-container-high rounded-lg mb-md">
          <div className="w-8 h-8 bg-primary rounded flex items-center justify-center">
            <span
              className="material-symbols-outlined text-on-primary text-headline-sm"
              style={{ fontVariationSettings: "'FILL' 1" }}
            >
              shield
            </span>
          </div>
          <div>
            <div className="font-label-caps text-label-caps text-primary">Global Ops</div>
            <div className="text-xs text-on-surface-variant truncate">US-East-1 Cluster</div>
          </div>
        </div>
        <button
          onClick={handleNewScan}
          className="w-full py-sm bg-primary text-on-primary font-bold rounded flex items-center justify-center gap-xs hover:bg-primary-container transition-all"
        >
          <span className="material-symbols-outlined text-sm">add</span> New Scan
        </button>
      </div>
      <nav className="flex-1 space-y-xs px-sm">
        {menuItems.map((item) => {
          const actualPageId = item.id === 'inventory' ? 'assets' : item.id === 'vulnerabilities' ? 'threats' : item.id;
          return (
            <button
              key={item.id}
              onClick={() => onNavigate(actualPageId)}
              className={`flex items-center gap-sm px-md py-sm rounded transition-all scale-95 duration-150 font-label-caps text-label-caps w-full text-left ${
                currentPage === actualPageId || (item.id === 'inventory' && currentPage === 'assets') || (item.id === 'vulnerabilities' && currentPage === 'threats')
                  ? 'text-primary font-bold bg-surface-variant/50 border-r-2 border-primary'
                  : 'text-on-surface-variant hover:bg-surface-variant hover:text-on-surface'
              }`}
            >
              <span
                className="material-symbols-outlined"
                style={currentPage === actualPageId || (item.id === 'inventory' && currentPage === 'assets') || (item.id === 'vulnerabilities' && currentPage === 'threats') ? { fontVariationSettings: "'FILL' 1" } : {}}
              >
                {item.icon}
              </span>
              {item.label}
            </button>
          );
        })}
      </nav>
      <div className="px-sm pt-md border-t border-outline-variant mt-md">
        {bottomItems.map((item) => (
          <button
            key={item.id}
            onClick={() => handleBottomItem(item.id, item.label)}
            className="flex items-center gap-sm px-md py-sm rounded transition-all hover:bg-surface-variant text-on-surface-variant mb-xs w-full text-left font-label-caps text-label-caps"
          >
            <span className="material-symbols-outlined">{item.icon}</span>
            {item.label}
          </button>
        ))}
      </div>
    </aside>
  );
};

export default Sidebar;
