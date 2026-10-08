import React, { useState, useEffect } from 'react';
import { History, ShieldAlert, CheckCircle2, XCircle, Search, RefreshCw, Filter, FileText } from 'lucide-react';
import { api } from '../api';

export default function AuditLogViewer({ user, showToast }) {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [actionFilter, setActionFilter] = useState('');
  const [error, setError] = useState('');

  const isLawyer = user?.role === 'lawyer';

  useEffect(() => {
    if (isLawyer) {
      fetchLogs();
    }
  }, [isLawyer, actionFilter]);

  const fetchLogs = async () => {
    setLoading(true);
    setError('');
    try {
      const data = await api.getAuditLogs(actionFilter);
      setLogs(data);
    } catch (err) {
      setError(err.message || 'Access denied: Unable to fetch audit logs.');
      showToast(err.message || 'Access denied', 'danger');
    } finally {
      setLoading(false);
    }
  };

  if (!isLawyer) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '3rem 1.5rem' }}>
        <div style={{
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'center',
          width: '56px',
          height: '56px',
          borderRadius: '50%',
          background: '#fee2e2',
          color: '#dc2626',
          marginBottom: '1rem'
        }}>
          <ShieldAlert size={32} />
        </div>
        <h3 style={{ fontSize: '1.25rem', fontWeight: 700, color: '#991b1b' }}>
          Access Denied: Lawyer Clearance Required
        </h3>
        <p style={{ color: '#64748b', fontSize: '0.9rem', maxWidth: '460px', margin: '0.5rem auto' }}>
          Confidential audit trails are restricted by backend Role-Based Access Control (RBAC).
          Your role (<strong>{user?.role?.toUpperCase()}</strong>) does not have authorization to inspect forensic activity logs.
        </p>
      </div>
    );
  }

  return (
    <div className="card">
      <div className="card-header">
        <div className="card-title">
          <History size={20} color="#3b82f6" />
          <span>Security & Compliance Audit Trail</span>
        </div>

        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <Filter size={15} color="#64748b" />
            <select
              className="form-select"
              style={{ padding: '0.35rem 0.65rem', fontSize: '0.8rem' }}
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
            >
              <option value="">All Security Events</option>
              <option value="Login">Login & Authentication</option>
              <option value="OTP">OTP Verification</option>
              <option value="encrypted">Document Encryption</option>
              <option value="shared">Document Sharing</option>
              <option value="downloaded">Document Downloads</option>
              <option value="denied">Access Denied (Violations)</option>
              <option value="revoked">Access Revocation</option>
            </select>
          </div>

          <button
            onClick={fetchLogs}
            disabled={loading}
            className="btn btn-outline btn-sm"
          >
            <RefreshCw className={loading ? 'animate-spin' : ''} size={14} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {error ? (
        <div className="alert alert-danger">{error}</div>
      ) : logs.length === 0 ? (
        <div style={{ padding: '2rem', textAlign: 'center', color: '#64748b', fontStyle: 'italic' }}>
          {loading ? 'Loading audit records...' : 'No audit records matching filter.'}
        </div>
      ) : (
        <div className="table-container">
          <table className="table">
            <thead>
              <tr>
                <th>Timestamp (UTC)</th>
                <th>Action</th>
                <th>Status</th>
                <th>User / Role</th>
                <th>Doc ID</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log) => {
                const dateStr = new Date(log.timestamp).toLocaleString();
                const isFail = !log.success;
                const isViolation = log.action.toLowerCase().includes('denied') || isFail;

                return (
                  <tr key={log.id} style={isViolation ? { backgroundColor: '#fff5f5' } : {}}>
                    <td style={{ whiteSpace: 'nowrap', fontSize: '0.8rem', color: '#64748b', fontFamily: 'monospace' }}>
                      {dateStr}
                    </td>
                    <td>
                      <span style={{ fontWeight: 600, color: isViolation ? '#dc2626' : '#0f172a' }}>
                        {log.action}
                      </span>
                    </td>
                    <td>
                      {log.success ? (
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.25rem', color: '#059669', fontSize: '0.75rem', fontWeight: 600 }}>
                          <CheckCircle2 size={13} /> OK
                        </span>
                      ) : (
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.25rem', color: '#dc2626', fontSize: '0.75rem', fontWeight: 600 }}>
                          <XCircle size={13} /> REJECTED
                        </span>
                      )}
                    </td>
                    <td>
                      <div style={{ fontSize: '0.85rem' }}>{log.user_email || 'Unauthenticated'}</div>
                      {log.user_role && (
                        <span className={`role-badge role-${log.user_role}`} style={{ fontSize: '0.65rem' }}>
                          {log.user_role}
                        </span>
                      )}
                    </td>
                    <td>
                      {log.document_id ? (
                        <span style={{ fontFamily: 'monospace', fontWeight: 600 }}>#{log.document_id}</span>
                      ) : (
                        <span style={{ color: '#94a3b8' }}>—</span>
                      )}
                    </td>
                    <td style={{ fontSize: '0.8rem', color: '#475569', maxWidth: '320px' }}>
                      {log.details || '—'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
