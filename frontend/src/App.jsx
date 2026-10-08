import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import AuthView from './components/AuthView';
import Dashboard from './components/Dashboard';
import { api, getStoredUser, setStoredUser, removeStoredUser, setAuthToken, removeAuthToken } from './api';
import { CheckCircle2, AlertTriangle, Info, X } from 'lucide-react';

export default function App() {
  const [user, setUser] = useState(getStoredUser());
  const [toasts, setToasts] = useState([]);

  useEffect(() => {
    const handleUnauthorized = () => {
      setUser(null);
      showToast('Session expired or unauthorized. Please sign in.', 'danger');
    };

    window.addEventListener('auth:unauthorized', handleUnauthorized);
    return () => window.removeEventListener('auth:unauthorized', handleUnauthorized);
  }, []);

  const showToast = (message, type = 'info') => {
    const id = Date.now() + Math.random();
    setToasts((prev) => [...prev, { id, message, type }]);

    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 4000);
  };

  const removeToast = (id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  };

  const handleAuthSuccess = (tokenData) => {
    setAuthToken(tokenData.access_token);
    setStoredUser(tokenData.user);
    setUser(tokenData.user);
  };

  const handleLogout = async () => {
    await api.logout();
    setUser(null);
    showToast('Signed out securely.', 'info');
  };

  return (
    <div>
      <Navbar user={user} onLogout={handleLogout} />

      <main className="main-content">
        {!user ? (
          <AuthView onAuthSuccess={handleAuthSuccess} showToast={showToast} />
        ) : (
          <Dashboard user={user} showToast={showToast} />
        )}
      </main>

      {/* Floating Notifications / Toasts */}
      <div className="toast-container">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={`toast toast-${t.type}`}
            style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              {t.type === 'success' && <CheckCircle2 size={16} />}
              {t.type === 'danger' && <AlertTriangle size={16} />}
              {t.type === 'info' && <Info size={16} />}
              <span style={{ fontSize: '0.85rem' }}>{t.message}</span>
            </div>
            <button
              onClick={() => removeToast(t.id)}
              style={{ background: 'none', border: 'none', color: 'rgba(255,255,255,0.7)', cursor: 'pointer' }}
            >
              <X size={14} />
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
