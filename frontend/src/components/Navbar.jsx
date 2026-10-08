import React from 'react';
import { Shield, Lock, LogOut, User, CheckCircle2 } from 'lucide-react';

export default function Navbar({ user, onLogout }) {
  const getRoleClass = (role) => {
    switch (role?.toLowerCase()) {
      case 'lawyer': return 'role-lawyer';
      case 'associate': return 'role-associate';
      case 'client': return 'role-client';
      default: return 'role-associate';
    }
  };

  return (
    <nav className="navbar">
      <div className="nav-brand">
        <Shield size={26} color="#60a5fa" />
        <span>LegaVault</span>
        <span className="nav-brand-badge">Objective 1 • Secure Transfer</span>
      </div>

      {user && (
        <div className="nav-user">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <User size={16} color="#94a3b8" />
            <span style={{ fontSize: '0.875rem', fontWeight: 500 }}>{user.full_name}</span>
            <span className={`role-badge ${getRoleClass(user.role)}`}>
              <Lock size={11} /> {user.role}
            </span>
          </div>

          <button
            onClick={onLogout}
            className="btn btn-outline btn-sm"
            style={{ color: '#f8fafc', borderColor: '#334155' }}
            title="Sign out securely"
          >
            <LogOut size={14} />
            <span>Logout</span>
          </button>
        </div>
      )}
    </nav>
  );
}
