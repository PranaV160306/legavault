import React, { useState, useEffect } from 'react';
import {
  FileText, Upload, Shield, Lock, History, Users, Key,
  CheckCircle2, AlertCircle, Info, RefreshCw, HardDrive
} from 'lucide-react';
import DocumentList from './DocumentList';
import UploadModal from './UploadModal';
import ShareModal from './ShareModal';
import AuditLogViewer from './AuditLogViewer';
import { api } from '../api';

export default function Dashboard({ user, showToast }) {
  const [activeTab, setActiveTab] = useState('documents'); // 'documents' | 'shared' | 'audit' | 'system'
  const [documents, setDocuments] = useState([]);
  const [loading, setLoading] = useState(true);
  const [isUploadOpen, setIsUploadOpen] = useState(false);
  const [shareDoc, setShareDoc] = useState(null);
  const [systemHealth, setSystemHealth] = useState(null);

  const isLawyer = user?.role === 'lawyer';

  useEffect(() => {
    loadDocuments();
    loadHealth();
  }, []);

  const loadDocuments = async () => {
    setLoading(true);
    try {
      const data = await api.getDocuments();
      setDocuments(data);
    } catch (err) {
      showToast(err.message || 'Failed to fetch documents', 'danger');
    } finally {
      setLoading(false);
    }
  };

  const loadHealth = async () => {
    try {
      const h = await api.getHealth();
      setSystemHealth(h);
    } catch (e) {
      // ignore
    }
  };

  const myUploads = documents.filter((d) => d.is_owner);
  const sharedWithMe = documents.filter((d) => !d.is_owner);

  return (
    <div>
      {/* Top Crypto & RBAC Status Banner */}
      <div className="crypto-banner">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
          <div style={{
            background: 'rgba(59, 130, 246, 0.2)',
            padding: '0.5rem',
            borderRadius: '8px',
            color: '#60a5fa'
          }}>
            <Shield size={24} />
          </div>
          <div>
            <div style={{ fontWeight: 600, fontSize: '0.95rem' }}>
              AES-256-GCM Secure Transfer Engine
            </div>
            <div style={{ fontSize: '0.775rem', color: '#94a3b8' }}>
              Unique 96-bit nonce/IV per file • SHA-256 integrity verification • SQLite audit log trail
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
          <span className="crypto-badge">
            <CheckCircle2 size={12} /> RBAC ENFORCED
          </span>
          <span className="crypto-badge" style={{ borderColor: '#60a5fa', color: '#93c5fd', background: 'rgba(37,99,235,0.2)' }}>
            <Key size={12} /> 2FA OTP ACTIVE
          </span>
        </div>
      </div>

      {/* Main Dashboard Navigation & Actions */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
        <div className="tabs" style={{ marginBottom: 0 }}>
          <button
            onClick={() => setActiveTab('documents')}
            className={`tab ${activeTab === 'documents' ? 'active' : ''}`}
          >
            <Lock size={16} />
            <span>Secure Documents ({documents.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('shared')}
            className={`tab ${activeTab === 'shared' ? 'active' : ''}`}
          >
            <Users size={16} />
            <span>Shared With Me ({sharedWithMe.length})</span>
          </button>

          {isLawyer && (
            <button
              onClick={() => setActiveTab('audit')}
              className={`tab ${activeTab === 'audit' ? 'active' : ''}`}
            >
              <History size={16} />
              <span>Audit Logs</span>
            </button>
          )}

          <button
            onClick={() => setActiveTab('system')}
            className={`tab ${activeTab === 'system' ? 'active' : ''}`}
          >
            <Info size={16} />
            <span>System Spec</span>
          </button>
        </div>

        {/* Upload Button: Visible to Lawyer only! (Backend RBAC strictly enforces this as well) */}
        {isLawyer && (
          <button
            onClick={() => setIsUploadOpen(true)}
            className="btn btn-primary"
            style={{ padding: '0.55rem 1.1rem' }}
          >
            <Upload size={16} />
            <span>Encrypt & Upload Document</span>
          </button>
        )}
      </div>

      {/* TAB CONTENT */}
      {activeTab === 'documents' && (
        <DocumentList
          documents={documents}
          user={user}
          loading={loading}
          onRefresh={loadDocuments}
          onOpenShare={(doc) => setShareDoc(doc)}
          showToast={showToast}
        />
      )}

      {activeTab === 'shared' && (
        <DocumentList
          documents={sharedWithMe}
          user={user}
          loading={loading}
          onRefresh={loadDocuments}
          onOpenShare={(doc) => setShareDoc(doc)}
          showToast={showToast}
        />
      )}

      {activeTab === 'audit' && (
        <AuditLogViewer user={user} showToast={showToast} />
      )}

      {activeTab === 'system' && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Shield size={20} color="#2563eb" />
              <span>Objective 1 Architecture & Security Specs</span>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
            <div style={{ padding: '1rem', background: '#f8fafc', borderRadius: '6px', border: '1px solid #e2e8f0' }}>
              <div style={{ fontWeight: 600, color: '#1e3a8a', marginBottom: '0.25rem' }}>Cryptography</div>
              <div style={{ fontSize: '0.825rem', color: '#475569' }}>
                Algorithm: <strong>AES-256-GCM</strong> (Authenticated)<br />
                Key Size: 256 bits (32 bytes via HKDF-SHA256)<br />
                Nonce / IV: 96-bit (12 bytes) cryptographically random per file<br />
                Auth Tag: 128-bit (16 bytes) tamper prevention
              </div>
            </div>

            <div style={{ padding: '1rem', background: '#f8fafc', borderRadius: '6px', border: '1px solid #e2e8f0' }}>
              <div style={{ fontWeight: 600, color: '#1e3a8a', marginBottom: '0.25rem' }}>Access Control (RBAC)</div>
              <div style={{ fontSize: '0.825rem', color: '#475569' }}>
                Enforcement: <strong>Backend API Level</strong><br />
                Roles: Lawyer, Associate, Client<br />
                Lawyer: Upload, Encrypt, Share, Revoke, Audit<br />
                Associate & Client: Authorized shared view/download only
              </div>
            </div>

            <div style={{ padding: '1rem', background: '#f8fafc', borderRadius: '6px', border: '1px solid #e2e8f0' }}>
              <div style={{ fontWeight: 600, color: '#1e3a8a', marginBottom: '0.25rem' }}>Two-Factor OTP</div>
              <div style={{ fontSize: '0.825rem', color: '#475569' }}>
                Code: 6-digit random (secrets.randbelow)<br />
                Expiry: 5 minutes<br />
                Single-use constraint & cooldown rate limit<br />
                Storage: keyed HMAC-SHA-256 (never plain text)
              </div>
            </div>

            <div style={{ padding: '1rem', background: '#f8fafc', borderRadius: '6px', border: '1px solid #e2e8f0' }}>
              <div style={{ fontWeight: 600, color: '#1e3a8a', marginBottom: '0.25rem' }}>Audit Trail</div>
              <div style={{ fontSize: '0.825rem', color: '#475569' }}>
                Storage: SQLite table <code>audit_logs</code><br />
                Logged: Upload, Encrypt, Share, Download, Revoke, Violations<br />
                Restricted to Lawyer role only<br />
                Secrets excluded: No passwords, keys, or OTPs logged
              </div>
            </div>
          </div>

          {systemHealth && (
            <div style={{ background: '#0f172a', color: '#f8fafc', padding: '1rem', borderRadius: '6px', fontSize: '0.8rem', fontFamily: 'monospace' }}>
              <div>[HEALTH CHECK] Status: {systemHealth.status}</div>
              <div>Service: {systemHealth.service}</div>
              <div>OTP Mode: {systemHealth.otp_mode}</div>
              <div>Vault Path: {systemHealth.vault_path}</div>
            </div>
          )}
        </div>
      )}

      {/* Modals */}
      <UploadModal
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        onUploadSuccess={() => loadDocuments()}
        showToast={showToast}
      />

      <ShareModal
        isOpen={!!shareDoc}
        onClose={() => setShareDoc(null)}
        document={shareDoc}
        onShareUpdated={() => {
          loadDocuments();
          // Update currently viewed share document
          if (shareDoc) {
            api.getDocument(shareDoc.id).then((updated) => setShareDoc(updated)).catch(() => {});
          }
        }}
        showToast={showToast}
      />
    </div>
  );
}
