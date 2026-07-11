import { useState } from 'react';
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import BottomNav from './components/BottomNav';
import OverviewPage from './pages/OverviewPage';
import AssetsPage from './pages/AssetsPage';
import ThreatsPage from './pages/ThreatsPage';
import CompliancePage from './pages/CompliancePage';
import SettingsPage from './pages/SettingsPage';
import LogsPage from './pages/LogsPage';
import LoginPage from './pages/LoginPage';
import AlertProvider from './components/AlertProvider';
import { auth, getToken } from './services/api';

function MainAppContent() {
  const [currentPage, setCurrentPage] = useState('overview');
  const [isAuthenticated, setIsAuthenticated] = useState(!!getToken());

  const handleNavigate = (page: string) => {
    setCurrentPage(page);
  };

  const handleLogout = () => {
    auth.logout();
    setIsAuthenticated(false);
  };

  if (!isAuthenticated) {
    return <LoginPage onLogin={() => setIsAuthenticated(true)} />;
  }

  const renderPage = () => {
    switch (currentPage) {
      case 'overview':
        return <OverviewPage />;
      case 'assets':
      case 'inventory':
        return <AssetsPage />;
      case 'threats':
      case 'vulnerabilities':
        return <ThreatsPage />;
      case 'compliance':
        return <CompliancePage />;
      case 'settings':
        return <SettingsPage />;
      case 'logs':
        return <LogsPage />;
      default:
        return <OverviewPage />;
    }
  };

  const showSidebar = ['overview', 'compliance', 'inventory', 'vulnerabilities', 'assets', 'threats', 'logs', 'settings'].includes(
    currentPage
  );

  return (
    <div className="min-h-screen bg-background text-on-surface font-body-md">
      <Header currentPage={currentPage} onNavigate={handleNavigate} onLogout={handleLogout} />
      <div className="flex">
        <Sidebar currentPage={currentPage} onNavigate={handleNavigate} visible={showSidebar} />
        <div className={showSidebar ? 'flex-1 md:ml-60' : 'flex-1'}>
          {renderPage()}
        </div>
      </div>
      <BottomNav currentPage={currentPage} onNavigate={handleNavigate} />
    </div>
  );
}

function App() {
  return (
    <AlertProvider>
      <MainAppContent />
    </AlertProvider>
  );
}

export default App;

