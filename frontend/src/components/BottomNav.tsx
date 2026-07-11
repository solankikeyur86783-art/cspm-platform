interface BottomNavProps {
  currentPage: string;
  onNavigate: (page: string) => void;
}

const BottomNav = ({ currentPage, onNavigate }: BottomNavProps) => {
  const navItems = [
    { id: 'overview', icon: 'dashboard', label: 'Overview' },
    { id: 'compliance', icon: 'fact_check', label: 'Compliance' },
    { id: 'threats', icon: 'radar', label: 'Threats' },
    { id: 'assets', icon: 'inventory_2', label: 'Assets' },
  ];

  return (
    <nav className="md:hidden fixed bottom-0 left-0 w-full z-50 flex justify-around items-center px-2 h-16 bg-surface-container-lowest border-t border-outline-variant/10">
      {navItems.map((item) => (
        <button
          key={item.id}
          onClick={() => onNavigate(item.id)}
          className={`flex flex-col items-center justify-center px-3 py-1 transition-transform duration-150 ${
            currentPage === item.id
              ? 'bg-primary-container/20 text-primary rounded-xl scale-95'
              : 'text-on-surface-variant hover:text-on-surface'
          }`}
        >
          <span
            className="material-symbols-outlined"
            style={currentPage === item.id ? { fontVariationSettings: "'FILL' 1" } : {}}
          >
            {item.icon}
          </span>
          <span className="font-label-caps text-label-caps mt-1">{item.label}</span>
        </button>
      ))}
    </nav>
  );
};

export default BottomNav;
