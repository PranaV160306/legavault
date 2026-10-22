import React, { useState, useEffect } from 'react';
import { Shield, Lock, Key, UserCheck, AlertCircle, RefreshCw, CheckCircle2 } from 'lucide-react';
import { api } from '../api';

export default function AuthView({ onAuthSuccess, showToast }) {
  const [view, setView] = useState('login'); // 'login' | 'register' | 'otp'
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [role, setRole] = useState('lawyer');
  const [lawyerRegistrationCode, setLawyerRegistrationCode] = useState('');
  const [otp, setOtp] = useState('');
  
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [resendCooldown, setResendCooldown] = useState(0);
  const [otpMode, setOtpMode] = useState(null);

  useEffect(() => {
    api.getHealth().then((health) => setOtpMode(health.otp_mode)).catch(() => setOtpMode(null));
  }, []);

  // Cooldown timer
  useEffect(() => {
    let timer;
    if (resendCooldown > 0) {
      timer = setInterval(() => {
        setResendCooldown((prev) => prev - 1);
      }, 1000);
    }
    return () => clearInterval(timer);
  }, [resendCooldown]);

  const handleQuickFill = (accRole) => {
    if (accRole === 'lawyer') {
      setEmail('lawyer@test.com');
      setPassword('LawyerPass123!');
    } else if (accRole === 'associate') {
      setEmail('associate@test.com');
      setPassword('AssociatePass123!');
    } else if (accRole === 'client') {
      setEmail('client@test.com');
      setPassword('ClientPass123!');
    }
    setError('');
  };

  const handleLoginSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await api.login(email, password);
      showToast('Credentials verified. Please enter the 6-digit OTP.', 'info');
      setView('otp');
      setResendCooldown(60);
    } catch (err) {
      setError(err.message || 'Invalid credentials');
      showToast('Invalid credentials. Access rejected.', 'danger');
    } finally {
      setLoading(false);
    }
  };

  const handleRegisterSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await api.register(email, fullName, password, role, lawyerRegistrationCode);
      showToast(`Account registered as ${role.toUpperCase()}. Please sign in.`, 'success');
      setView('login');
    } catch (err) {
      setError(err.message || 'Registration failed');
      showToast(err.message || 'Registration failed', 'danger');
    } finally {
      setLoading(false);
    }
  };

  const handleOtpSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const data = await api.verifyOtp(email, otp);
      showToast('Login successful! Welcome to LegaVault.', 'success');
      onAuthSuccess(data);
    } catch (err) {
      const msg = err.message || 'Invalid OTP';
      setError(msg);
      if (msg.toLowerCase().includes('expired')) {
        showToast('OTP expired. Please request a new code.', 'danger');
      } else {
        showToast(msg, 'danger');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleResendOtp = async () => {
    if (resendCooldown > 0) return;
    setError('');
    try {
      await api.resendOtp(email);
      setResendCooldown(60);
      showToast(otpMode === 'DEVELOPMENT' ? 'A fresh OTP was written to the backend console.' : 'A fresh OTP was sent to your email.', 'info');
    } catch (err) {
      setError(err.message || 'Could not resend OTP');
      showToast(err.message, 'danger');
    }
  };

  return (
    <div style={{ maxWidth: '480px', margin: '3rem auto', width: '100%' }}>
      <div className="card" style={{ padding: '2rem' }}>
        <div style={{ textAlign: 'center', marginBottom: '1.75rem' }}>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: '56px',
            height: '56px',
            borderRadius: '16px',
            background: '#eff6ff',
            color: '#1d4ed8',
            marginBottom: '1rem'
          }}>
            <Shield size={32} />
          </div>
          <h2 style={{ fontSize: '1.5rem', fontWeight: 700, color: '#0f172a' }}>
            {view === 'otp' ? 'Two-Factor Authentication' : view === 'login' ? 'LegaVault Sign In' : 'Create Legal Account'}
          </h2>
          <p style={{ fontSize: '0.875rem', color: '#64748b', marginTop: '0.25rem' }}>
            {view === 'otp'
              ? 'Enter the 6-digit email verification code to verify your identity.'
              : view === 'login'
              ? 'Confidential role-based document workspace.'
              : 'Register as Lawyer, Associate, or Client.'}
          </p>
        </div>

        {error && (
          <div className="alert alert-danger">
            <AlertCircle size={16} />
            <span>{error}</span>
          </div>
        )}

        {/* VIEW 1: LOGIN */}
        {view === 'login' && (
          <form onSubmit={handleLoginSubmit}>
            <div className="form-group">
              <label className="form-label">Email Address</label>
              <input
                type="email"
                required
                className="form-input"
                placeholder="name@firm.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>

            <div className="form-group">
              <label className="form-label">Password</label>
              <input
                type="password"
                required
                className="form-input"
                placeholder="••••••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn btn-primary"
              style={{ width: '100%', padding: '0.75rem', marginTop: '0.5rem' }}
            >
              {loading ? <RefreshCw className="animate-spin" size={16} /> : <Lock size={16} />}
              <span>Verify Credentials & Request OTP</span>
            </button>

            {/* Quick Test Accounts Fill */}
            <div style={{ marginTop: '1.75rem', paddingTop: '1.25rem', borderTop: '1px solid #e2e8f0' }}>
              <span style={{ fontSize: '0.75rem', fontWeight: 600, color: '#64748b', textTransform: 'uppercase' }}>
                Quick Test Accounts:
              </span>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '0.5rem', marginTop: '0.5rem' }}>
                <button
                  type="button"
                  onClick={() => handleQuickFill('lawyer')}
                  className="btn btn-outline btn-sm"
                  style={{ fontSize: '0.75rem', color: '#4338ca', borderColor: '#c7d2fe' }}
                >
                  Lawyer
                </button>
                <button
                  type="button"
                  onClick={() => handleQuickFill('associate')}
                  className="btn btn-outline btn-sm"
                  style={{ fontSize: '0.75rem', color: '#0284c7', borderColor: '#bae6fd' }}
                >
                  Associate
                </button>
                <button
                  type="button"
                  onClick={() => handleQuickFill('client')}
                  className="btn btn-outline btn-sm"
                  style={{ fontSize: '0.75rem', color: '#059669', borderColor: '#a7f3d0' }}
                >
                  Client
                </button>
              </div>
            </div>

            <div style={{ textAlign: 'center', marginTop: '1.5rem', fontSize: '0.85rem' }}>
              <span style={{ color: '#64748b' }}>Don't have an account? </span>
              <button
                type="button"
                onClick={() => { setView('register'); setError(''); }}
                style={{ background: 'none', border: 'none', color: '#2563eb', fontWeight: 600, cursor: 'pointer' }}
              >
                Register here
              </button>
            </div>
          </form>
        )}

        {/* VIEW 2: REGISTER */}
        {view === 'register' && (
          <form onSubmit={handleRegisterSubmit}>
            <div className="form-group">
              <label className="form-label">Full Name</label>
              <input
                type="text"
                required
                className="form-input"
                placeholder="Advocate John Doe"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
              />
            </div>

            <div className="form-group">
              <label className="form-label">Email Address</label>
              <input
                type="email"
                required
                className="form-input"
                placeholder="user@legavault.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>

            <div className="form-group">
              <label className="form-label">Role (RBAC Enforced)</label>
              <select
                className="form-select"
                value={role}
                onChange={(e) => setRole(e.target.value)}
              >
                <option value="lawyer">Lawyer (Full: Upload, AES Encrypt, Share, Revoke, Audit Logs)</option>
                <option value="associate">Associate (Restricted: View & Download shared documents)</option>
                <option value="client">Client (Restricted: View & Download confidential documents)</option>
              </select>
            </div>

            {role === 'lawyer' && (
              <div className="form-group">
                <label className="form-label">Lawyer setup code</label>
                <input
                  type="password"
                  required
                  autoComplete="off"
                  className="form-input"
                  value={lawyerRegistrationCode}
                  onChange={(e) => setLawyerRegistrationCode(e.target.value)}
                  placeholder="Provided by the project administrator"
                />
                <small style={{ color: '#64748b' }}>Required to register an account with lawyer privileges.</small>
              </div>
            )}

            <div className="form-group">
              <label className="form-label">Password</label>
              <input
                type="password"
                required
                minLength={12}
                className="form-input"
                placeholder="••••••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn btn-primary"
              style={{ width: '100%', padding: '0.75rem', marginTop: '0.5rem' }}
            >
              {loading ? <RefreshCw className="animate-spin" size={16} /> : <UserCheck size={16} />}
              <span>Create Account</span>
            </button>

            <div style={{ textAlign: 'center', marginTop: '1.5rem', fontSize: '0.85rem' }}>
              <span style={{ color: '#64748b' }}>Already have an account? </span>
              <button
                type="button"
                onClick={() => { setView('login'); setError(''); }}
                style={{ background: 'none', border: 'none', color: '#2563eb', fontWeight: 600, cursor: 'pointer' }}
              >
                Sign In
              </button>
            </div>
          </form>
        )}

        {/* VIEW 3: OTP VERIFICATION */}
        {view === 'otp' && (
          <form onSubmit={handleOtpSubmit}>
            {otpMode === 'DEVELOPMENT' ? (
              <div className="alert alert-info" style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', gap: '0.35rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 600 }}>
                  <Key size={16} />
                  <span>Development OTP Mode Active</span>
                </div>
                <p style={{ fontSize: '0.8rem', opacity: 0.9 }}>
                  Check the <strong>backend development terminal</strong> for the 6-digit OTP for <strong>{email}</strong>. Development mode does not send email.
                </p>
              </div>
            ) : otpMode === 'EMAIL' ? (
              <div className="alert alert-info">
                Check the inbox for <strong>{email}</strong> for your 6-digit verification code. Check spam/junk if it does not arrive.
              </div>
            ) : null}

            <div className="form-group">
              <label className="form-label" style={{ textAlign: 'center', display: 'block' }}>Enter 6-Digit OTP Code</label>
              <div className="otp-container">
                <input
                  type="text"
                  maxLength={6}
                  required
                  autoFocus
                  className="form-input"
                  style={{
                    letterSpacing: '0.5rem',
                    textAlign: 'center',
                    fontSize: '1.75rem',
                    fontWeight: 700,
                    maxWidth: '220px',
                    margin: '0 auto',
                    padding: '0.5rem'
                  }}
                  placeholder="------"
                  value={otp}
                  onChange={(e) => setOtp(e.target.value.replace(/\D/g, ''))}
                />
              </div>
              <p style={{ textAlign: 'center', fontSize: '0.75rem', color: '#64748b' }}>
                Code expires in 5 minutes and is valid for a single use.
              </p>
            </div>

            <button
              type="submit"
              disabled={loading || otp.length !== 6}
              className="btn btn-primary"
              style={{ width: '100%', padding: '0.75rem', marginTop: '1rem' }}
            >
              {loading ? <RefreshCw className="animate-spin" size={16} /> : <CheckCircle2 size={16} />}
              <span>Verify OTP & Access Vault</span>
            </button>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '1.25rem', fontSize: '0.85rem' }}>
              <button
                type="button"
                onClick={() => { setView('login'); setOtp(''); setError(''); }}
                style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer' }}
              >
                ← Back to Login
              </button>

              <button
                type="button"
                onClick={handleResendOtp}
                disabled={resendCooldown > 0}
                style={{
                  background: 'none',
                  border: 'none',
                  color: resendCooldown > 0 ? '#94a3b8' : '#2563eb',
                  fontWeight: 600,
                  cursor: resendCooldown > 0 ? 'not-allowed' : 'pointer'
                }}
              >
                {resendCooldown > 0 ? `Resend OTP (${resendCooldown}s)` : 'Resend Code'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
