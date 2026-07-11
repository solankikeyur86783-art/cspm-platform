import { useState } from 'react';
import { auth } from '../services/api';

interface LoginPageProps {
  onLogin: () => void;
}

const LoginPage = ({ onLogin }: LoginPageProps) => {
  const [email, setEmail] = useState('admin@cspm.local');
  const [password, setPassword] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await auth.login(email, password);
      onLogin();
    } catch (err: any) {
      setError(err.message || 'Invalid credentials. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleDemoLogin = async () => {
    setEmail('admin@cspm.local');
    setPassword('Admin@CSPM123');
    setError('');
    setLoading(true);
    try {
      await auth.login('admin@cspm.local', 'Admin@CSPM123');
      onLogin();
    } catch (err: any) {
      // If backend isn't up yet, go in anyway for demo
      setError('Backend offline — launching demo mode.');
      setTimeout(onLogin, 1200);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-background flex items-center justify-center relative overflow-hidden">
      {/* Animated atmospheric background */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-[-20%] left-[-10%] w-[60%] h-[60%] bg-primary/15 rounded-full blur-[140px] animate-pulse" />
        <div className="absolute bottom-[-20%] right-[-10%] w-[50%] h-[50%] bg-secondary/10 rounded-full blur-[120px]" />
        <div className="absolute top-[40%] left-[40%] w-[30%] h-[30%] bg-tertiary/8 rounded-full blur-[100px] animate-pulse" style={{ animationDelay: '1s' }} />
        {/* Grid lines */}
        <div
          className="absolute inset-0 opacity-[0.03]"
          style={{
            backgroundImage: 'linear-gradient(rgba(100,255,200,0.5) 1px, transparent 1px), linear-gradient(90deg, rgba(100,255,200,0.5) 1px, transparent 1px)',
            backgroundSize: '60px 60px',
          }}
        />
      </div>

      <div className="relative z-10 w-full max-w-md px-4">
        {/* Logo / Brand */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-primary/15 border border-primary/30 mb-4 shadow-lg shadow-primary/20">
            <span
              className="material-symbols-outlined text-primary text-4xl"
              style={{ fontVariationSettings: "'FILL' 1" }}
            >
              security
            </span>
          </div>
          <h1 className="font-headline-sm text-2xl font-bold text-on-surface tracking-tight">
            SENTINEL CSPM
          </h1>
          <p className="text-on-surface-variant text-sm mt-1 font-body-sm">
            Cloud Security Posture Management
          </p>
        </div>

        {/* Card */}
        <div className="bg-surface-container-high border border-outline-variant/20 rounded-2xl p-8 shadow-2xl backdrop-blur-sm">
          <h2 className="font-headline-sm text-lg text-on-surface mb-1">Sign in to your account</h2>
          <p className="text-on-surface-variant text-xs font-body-sm mb-6">
            Enter your credentials to access the platform
          </p>

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Email */}
            <div className="space-y-1">
              <label className="block text-xs font-bold text-on-surface-variant uppercase tracking-wider">
                Email Address
              </label>
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 material-symbols-outlined text-on-surface-variant text-lg">
                  mail
                </span>
                <input
                  id="login-email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  className="w-full pl-10 pr-4 py-3 bg-surface-container-highest border border-outline-variant/30 rounded-lg text-sm text-on-surface placeholder-on-surface-variant/50 focus:outline-none focus:border-primary/60 focus:ring-1 focus:ring-primary/30 transition-all"
                  placeholder="admin@cspm.local"
                />
              </div>
            </div>

            {/* Password */}
            <div className="space-y-1">
              <label className="block text-xs font-bold text-on-surface-variant uppercase tracking-wider">
                Password
              </label>
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 material-symbols-outlined text-on-surface-variant text-lg">
                  lock
                </span>
                <input
                  id="login-password"
                  type={showPw ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  className="w-full pl-10 pr-12 py-3 bg-surface-container-highest border border-outline-variant/30 rounded-lg text-sm text-on-surface placeholder-on-surface-variant/50 focus:outline-none focus:border-primary/60 focus:ring-1 focus:ring-primary/30 transition-all"
                  placeholder="Enter password"
                />
                <button
                  type="button"
                  onClick={() => setShowPw(!showPw)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-on-surface-variant hover:text-on-surface transition-colors"
                >
                  <span className="material-symbols-outlined text-lg">
                    {showPw ? 'visibility_off' : 'visibility'}
                  </span>
                </button>
              </div>
            </div>

            {/* Error Message */}
            {error && (
              <div className="flex items-start gap-2 px-3 py-2.5 bg-error/10 border border-error/30 rounded-lg text-xs text-error">
                <span className="material-symbols-outlined text-sm shrink-0 mt-0.5" style={{ fontVariationSettings: "'FILL' 1" }}>
                  error
                </span>
                {error}
              </div>
            )}

            {/* Submit */}
            <button
              id="login-submit"
              type="submit"
              disabled={loading}
              className="w-full py-3 bg-primary text-on-primary rounded-lg font-bold text-sm hover:brightness-110 active:scale-[0.98] transition-all disabled:opacity-60 disabled:cursor-not-allowed flex items-center justify-center gap-2 shadow-lg shadow-primary/30 mt-2"
            >
              {loading ? (
                <>
                  <span className="material-symbols-outlined text-lg animate-spin">progress_activity</span>
                  Authenticating…
                </>
              ) : (
                <>
                  <span className="material-symbols-outlined text-lg">login</span>
                  Sign In
                </>
              )}
            </button>
          </form>

          {/* Divider */}
          <div className="flex items-center gap-3 my-5">
            <div className="flex-1 h-px bg-outline-variant/20" />
            <span className="text-xs text-on-surface-variant uppercase tracking-wider">or</span>
            <div className="flex-1 h-px bg-outline-variant/20" />
          </div>

          {/* Demo Login */}
          <button
            id="login-demo"
            onClick={handleDemoLogin}
            disabled={loading}
            className="w-full py-3 border border-outline-variant/30 rounded-lg text-sm text-on-surface-variant hover:text-on-surface hover:bg-surface-variant/30 transition-all flex items-center justify-center gap-2 font-medium"
          >
            <span className="material-symbols-outlined text-lg">play_circle</span>
            Continue with Demo Credentials
          </button>

          {/* Credentials hint */}
          <div className="mt-5 p-3 bg-surface-container-highest rounded-lg border border-outline-variant/15">
            <p className="text-xs text-on-surface-variant text-center">
              <span className="font-mono text-primary">admin@cspm.local</span>
              {' · '}
              <span className="font-mono text-primary">Admin@CSPM123</span>
            </p>
          </div>
        </div>

        {/* Footer */}
        <p className="text-center text-xs text-on-surface-variant mt-6">
          SENTINEL CSPM Platform · v1.0.0 · Secured by zero-trust
        </p>
      </div>
    </div>
  );
};

export default LoginPage;
