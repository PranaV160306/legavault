import React, { useState } from 'react';
import {
  FileText, Download, Share2, Shield, Lock, Users, RefreshCw
} from 'lucide-react';
import { api } from '../api';

export default function DocumentList({
  documents,
  user,
  loading,
  onRefresh,
  onOpenShare,
  showToast
}) {
  const [downloadingId, setDownloadingId] = useState(null);

  const handleDownload = async (doc) => {
    setDownloadingId(doc.id);
    try {
      await api.downloadDocument(doc.id, doc.original_filename);
      showToast('Document decrypted & downloaded successfully.', 'success');
    } catch (err) {
      showToast(err.message || 'Access denied or decryption failure.', 'danger');
    } finally {
      setDownloadingId(null);
    }
  };

  if (loading) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '3rem' }}>
        <RefreshCw className="animate-spin" size={28} color="#2563eb" />
        <p style={{ marginTop: '0.75rem', color: '#64748b' }}>Loading encrypted vault documents...</p>
      </div>
    );
  }

  if (documents.length === 0) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '3.5rem 1.5rem' }}>
        <div style={{
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'center',
          width: '56px',
          height: '56px',
          borderRadius: '50%',
          background: '#f1f5f9',
          color: '#64748b',
          marginBottom: '1rem'
        }}>
          <FileText size={28} />
        </div>
        <h3 style={{ fontSize: '1.15rem', fontWeight: 600, color: '#1e293b' }}>
          No Accessible Documents
        </h3>
        <p style={{ color: '#64748b', fontSize: '0.875rem', maxWidth: '420px', margin: '0.5rem auto' }}>
          {user?.role === 'lawyer'
            ? 'You have not uploaded any documents yet. Click "Encrypt & Upload" above to secure your first legal file.'
            : 'No confidential documents have been shared with your account yet.'}
        </p>
      </div>
    );
  }

  return (
    <div className="card">
      <div className="card-header">
        <div className="card-title">
          <Lock size={20} color="#059669" />
          <span>Encrypted Vault Records ({documents.length})</span>
        </div>
        <button onClick={onRefresh} className="btn btn-outline btn-sm">
          <RefreshCw size={13} />
          <span>Refresh</span>
        </button>
      </div>

      <div className="table-container">
        <table className="table">
          <thead>
            <tr>
              <th>Document</th>
              <th>Security & Hash</th>
              <th>Size</th>
              <th>Owner</th>
              <th>Shares</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {documents.map((doc) => {
              const dateStr = new Date(doc.created_at).toLocaleDateString();
              const isOwner = doc.is_owner;
              const isDownloading = downloadingId === doc.id;

              return (
                <tr key={doc.id}>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.65rem' }}>
                      <div style={{
                        marginTop: '0.2rem',
                        padding: '0.35rem',
                        borderRadius: '6px',
                        background: '#eff6ff',
                        color: '#2563eb'
                      }}>
                        <FileText size={18} />
                      </div>
                      <div>
                        <div style={{ fontWeight: 600, color: '#0f172a' }}>{doc.title}</div>
                        <div style={{ fontSize: '0.75rem', color: '#64748b' }}>
                          {doc.original_filename}
                        </div>
                        {doc.description && (
                          <div style={{ fontSize: '0.75rem', color: '#475569', marginTop: '0.2rem' }}>
                            {doc.description}
                          </div>
                        )}
                      </div>
                    </div>
                  </td>

                  <td>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                      <span className="crypto-badge">
                        <Shield size={11} /> AES-256-GCM
                      </span>
                      <span style={{ fontSize: '0.7rem', color: '#64748b', fontFamily: 'monospace' }} title={`Full SHA-256: ${doc.sha256_hash}`}>
                        SHA256: {doc.sha256_hash.substring(0, 10)}...
                      </span>
                    </div>
                  </td>

                  <td style={{ fontSize: '0.8rem', whiteSpace: 'nowrap' }}>
                    {(doc.file_size / 1024).toFixed(1)} KB
                  </td>

                  <td>
                    <div style={{ fontSize: '0.8rem', fontWeight: 500 }}>
                      {isOwner ? <span style={{ color: '#2563eb' }}>You (Owner)</span> : doc.owner_name || doc.owner_email}
                    </div>
                    <div style={{ fontSize: '0.7rem', color: '#64748b' }}>{dateStr}</div>
                  </td>

                  <td>
                    {isOwner ? (
                      <span style={{ fontSize: '0.8rem', display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}>
                        <Users size={13} color="#64748b" />
                        <span>{doc.shares?.length || 0} recipient(s)</span>
                      </span>
                    ) : (
                      <span style={{ fontSize: '0.75rem', color: '#059669', fontWeight: 500 }}>
                        Shared with you
                      </span>
                    )}
                  </td>

                  <td>
                    <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                      <button
                        onClick={() => handleDownload(doc)}
                        disabled={isDownloading}
                        className="btn btn-primary btn-sm"
                        title="Download and decrypt with verified AES-256-GCM key"
                      >
                        {isDownloading ? <RefreshCw className="animate-spin" size={13} /> : <Download size={13} />}
                        <span>Decrypt & Download</span>
                      </button>

                      {isOwner && user?.role === 'lawyer' && (
                        <button
                          onClick={() => onOpenShare(doc)}
                          className="btn btn-outline btn-sm"
                          title="Manage role-based sharing and access permissions"
                        >
                          <Share2 size={13} />
                          <span>Share / Revoke</span>
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
