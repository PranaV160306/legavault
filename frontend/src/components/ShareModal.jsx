import React, { useState, useEffect, useCallback } from 'react';
import { Share2, Users, Trash2, X, RefreshCw } from 'lucide-react';
import { api } from '../api';

export default function ShareModal({ isOpen, onClose, document, onShareUpdated, showToast }) {
  const [users, setUsers] = useState([]);
  const [selectedUserId, setSelectedUserId] = useState('');
  const [permission, setPermission] = useState('view');
  const [loading, setLoading] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  const loadUsers = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.getUsers();
      // Filter out the owner of the document
      const eligible = data.filter((u) => u.id !== document?.owner_id);
      setUsers(eligible);
      if (eligible.length > 0) {
        setSelectedUserId(eligible[0].id.toString());
      }
    } catch {
      setError('Failed to load registered users');
    } finally {
      setLoading(false);
    }
  }, [document?.owner_id]);

  useEffect(() => {
    if (isOpen) loadUsers();
  }, [isOpen, loadUsers]);

  if (!isOpen || !document) return null;

  const handleShare = async (e) => {
    e.preventDefault();
    if (!selectedUserId) return;

    setError('');
    setSubmitting(true);
    try {
      await api.shareDocument(document.id, parseInt(selectedUserId), permission);
      showToast('Document shared successfully with authorized recipient.', 'success');
      onShareUpdated();
    } catch (err) {
      setError(err.message || 'Failed to share document');
      showToast(err.message || 'Share failed', 'danger');
    } finally {
      setSubmitting(false);
    }
  };

  const handleRevoke = async (recipientId, recipientEmail) => {
    try {
      await api.revokeShare(document.id, recipientId);
      showToast(`Access revoked for ${recipientEmail}.`, 'success');
      onShareUpdated();
    } catch (err) {
      showToast(err.message || 'Failed to revoke access', 'danger');
    }
  };

  return (
    <div className="modal-overlay">
      <div className="modal-content" style={{ maxWidth: '580px' }}>
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Share2 size={18} color="#60a5fa" />
            <h3 style={{ fontSize: '1.1rem', fontWeight: 600 }}>Confidential Document Sharing</h3>
          </div>
          <button
            onClick={onClose}
            style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer' }}
          >
            <X size={20} />
          </button>
        </div>

        <div className="modal-body">
          <div style={{ marginBottom: '1.25rem', paddingBottom: '0.75rem', borderBottom: '1px solid #e2e8f0' }}>
            <div style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: '#64748b', fontWeight: 600 }}>Document</div>
            <div style={{ fontSize: '1rem', fontWeight: 600, color: '#0f172a' }}>{document.title}</div>
            <div style={{ fontSize: '0.8rem', color: '#64748b' }}>Original: {document.original_filename}</div>
          </div>

          {error && <div className="alert alert-danger" style={{ fontSize: '0.85rem' }}>{error}</div>}

          {/* Share form */}
          <form onSubmit={handleShare} style={{ marginBottom: '1.5rem' }}>
            <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr auto', gap: '0.5rem', alignItems: 'flex-end' }}>
              <div className="form-group" style={{ marginBottom: 0 }}>
                <label className="form-label" style={{ fontSize: '0.8rem' }}>Recipient (Associate / Client)</label>
                <select
                  className="form-select"
                  disabled={loading || users.length === 0}
                  value={selectedUserId}
                  onChange={(e) => setSelectedUserId(e.target.value)}
                >
                  {users.map((u) => (
                    <option key={u.id} value={u.id}>
                      {u.full_name} ({u.role.toUpperCase()}) - {u.email}
                    </option>
                  ))}
                </select>
              </div>

              <div className="form-group" style={{ marginBottom: 0 }}>
                <label className="form-label" style={{ fontSize: '0.8rem' }}>Permission</label>
                <select
                  className="form-select"
                  value={permission}
                  onChange={(e) => setPermission(e.target.value)}
                >
                  <option value="view">View & Decrypt</option>
                  <option value="download">Download</option>
                </select>
              </div>

              <button
                type="submit"
                disabled={submitting || loading || users.length === 0}
                className="btn btn-primary"
                style={{ padding: '0.6rem 1rem' }}
              >
                {submitting ? <RefreshCw className="animate-spin" size={14} /> : <Share2 size={14} />}
                <span>Grant</span>
              </button>
            </div>
          </form>

          {/* Current Active Shares */}
          <div>
            <div style={{ fontSize: '0.85rem', fontWeight: 600, color: '#334155', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <Users size={15} />
              <span>Active Authorized Recipients ({document.shares?.length || 0})</span>
            </div>

            {(!document.shares || document.shares.length === 0) ? (
              <div style={{ fontSize: '0.8rem', color: '#64748b', fontStyle: 'italic', padding: '0.5rem 0' }}>
                No external users currently have access to this document.
              </div>
            ) : (
              <div className="table-container">
                <table className="table" style={{ fontSize: '0.8rem' }}>
                  <thead>
                    <tr>
                      <th>Recipient</th>
                      <th>Role</th>
                      <th>Permission</th>
                      <th>Revoke</th>
                    </tr>
                  </thead>
                  <tbody>
                    {document.shares.map((s) => (
                      <tr key={s.id}>
                        <td>
                          <div style={{ fontWeight: 600 }}>{s.recipient_name || 'User'}</div>
                          <div style={{ color: '#64748b', fontSize: '0.75rem' }}>{s.recipient_email}</div>
                        </td>
                        <td>
                          <span className={`role-badge role-${s.recipient_role || 'associate'}`} style={{ fontSize: '0.65rem' }}>
                            {s.recipient_role}
                          </span>
                        </td>
                        <td>
                          <span style={{ textTransform: 'capitalize', color: '#0f172a' }}>{s.permission}</span>
                        </td>
                        <td>
                          <button
                            type="button"
                            onClick={() => handleRevoke(s.recipient_id, s.recipient_email)}
                            className="btn btn-danger btn-sm"
                            title="Revoke access immediately"
                          >
                            <Trash2 size={13} />
                            <span>Revoke</span>
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        <div className="modal-footer">
          <button type="button" onClick={onClose} className="btn btn-outline">
            Done
          </button>
        </div>
      </div>
    </div>
  );
}
