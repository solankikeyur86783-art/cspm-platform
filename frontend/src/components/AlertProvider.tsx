import { createContext, useContext, useState, useCallback, useRef, useEffect } from 'react';

type AlertType = 'success' | 'error' | 'warning' | 'info';

interface Alert {
  id: string;
  type: AlertType;
  title: string;
  message: string;
  duration: number;
  createdAt: number;
}

interface AlertContextType {
  showAlert: (type: AlertType, title: string, message: string, duration?: number) => void;
  dismissAlert: (id: string) => void;
}

const AlertContext = createContext<AlertContextType>({
  showAlert: () => {},
  dismissAlert: () => {},
});

export const useAlert = () => useContext(AlertContext);

const alertConfig: Record<AlertType, { icon: string; gradient: string; border: string; iconBg: string; progressColor: string }> = {
  success: {
    icon: 'check_circle',
    gradient: 'from-emerald-500/20 to-emerald-900/10',
    border: 'border-emerald-500/40',
    iconBg: 'bg-emerald-500/20 text-emerald-400',
    progressColor: 'bg-emerald-400',
  },
  error: {
    icon: 'error',
    gradient: 'from-red-500/20 to-red-900/10',
    border: 'border-red-500/40',
    iconBg: 'bg-red-500/20 text-red-400',
    progressColor: 'bg-red-400',
  },
  warning: {
    icon: 'warning',
    gradient: 'from-amber-500/20 to-amber-900/10',
    border: 'border-amber-500/40',
    iconBg: 'bg-amber-500/20 text-amber-400',
    progressColor: 'bg-amber-400',
  },
  info: {
    icon: 'info',
    gradient: 'from-blue-500/20 to-blue-900/10',
    border: 'border-blue-500/40',
    iconBg: 'bg-blue-500/20 text-blue-400',
    progressColor: 'bg-blue-400',
  },
};

export const AlertProvider = ({ children }: { children: React.ReactNode }) => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const timersRef = useRef<Map<string, number>>(new Map());

  const dismissAlert = useCallback((id: string) => {
    const timer = timersRef.current.get(id);
    if (timer) {
      clearTimeout(timer);
      timersRef.current.delete(id);
    }
    setAlerts((prev) => prev.filter((a) => a.id !== id));
  }, []);

  const showAlert = useCallback(
    (type: AlertType, title: string, message: string, duration = 5000) => {
      const id = `alert-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
      const alert: Alert = { id, type, title, message, duration, createdAt: Date.now() };
      setAlerts((prev) => [...prev.slice(-4), alert]);

      const timer = window.setTimeout(() => {
        dismissAlert(id);
      }, duration);
      timersRef.current.set(id, timer);
    },
    [dismissAlert]
  );

  useEffect(() => {
    return () => {
      timersRef.current.forEach((timer) => clearTimeout(timer));
    };
  }, []);

  return (
    <AlertContext.Provider value={{ showAlert, dismissAlert }}>
      {children}
      {/* Toast Container */}
      <div className="fixed top-16 right-4 z-[100] flex flex-col gap-3 max-w-sm w-full pointer-events-none">
        {alerts.map((alert, idx) => {
          const config = alertConfig[alert.type];
          return (
            <div
              key={alert.id}
              className={`pointer-events-auto alert-slide-in rounded-xl border ${config.border} bg-gradient-to-r ${config.gradient} backdrop-blur-xl shadow-2xl overflow-hidden`}
              style={{ animationDelay: `${idx * 50}ms` }}
            >
              <div className="flex items-start gap-3 p-4">
                <div className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 ${config.iconBg}`}>
                  <span
                    className="material-symbols-outlined text-xl"
                    style={{ fontVariationSettings: "'FILL' 1" }}
                  >
                    {config.icon}
                  </span>
                </div>
                <div className="flex-1 min-w-0">
                  <div className="font-semibold text-sm text-on-surface">{alert.title}</div>
                  <div className="text-xs text-on-surface-variant mt-0.5 leading-relaxed">{alert.message}</div>
                </div>
                <button
                  onClick={() => dismissAlert(alert.id)}
                  className="text-on-surface-variant hover:text-on-surface transition-colors shrink-0"
                >
                  <span className="material-symbols-outlined text-lg">close</span>
                </button>
              </div>
              {/* Progress bar */}
              <div className="h-0.5 w-full bg-white/5">
                <div
                  className={`h-full ${config.progressColor} alert-progress`}
                  style={{ animationDuration: `${alert.duration}ms` }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </AlertContext.Provider>
  );
};

export default AlertProvider;
