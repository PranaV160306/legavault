import React, { useState } from 'react';
import { Shield, Upload, Lock, X, RefreshCw } from 'lucide-react';
import { api } from '../api';

export default function UploadModal({ isOpen, onClose, onUploadSuccess, showToast }) {
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [file, setFile] = useState(null);
  const [encrypting, setEncrypting] = useState(false);
  const [error, setError] = useState('');

  if (!isOpen) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!file) {
      setError('Please select a file to encrypt and upload.');
      return;
    }

    setError('');
    setEncrypting(true);

    try {
      const doc = await api.uploadDocument(title, description, file);
      showToast('Document encrypted and stored securely in vault.', 'success');
      onUploadSuccess(doc);
      onClose();
    } catch (err) {
      setError(err.message || 'Upload failed');
      showToast(err.message || 'Encryption/upload failed', 'danger');
    } finally {
      setEncrypting(false);
    }
  };

  return (
    <div className="modal-overlay">
      <div className="modal-content">
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Lock size={18} color="#60a5fa" />
            <h3 style={{ fontSize: '1.1rem', fontWeight: 600 }}>Encrypt & Upload Document</h3>
          </div>
          <button
            onClick={onClose}
            disabled={encrypting}
            style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer' }}
          >
            <X size={20} />
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="modal-body">
            <div className="alert alert-info" style={{ fontSize: '0.8rem' }}>
              <Shield size={16} />
              <span>
                <strong>AES-256-GCM Protection:</strong> File contents are encrypted server-side with a unique 96-bit nonce before touching disk storage.
              </span>
            </div>

            {error && (
              <div className="alert alert-danger" style={{ fontSize: '0.85rem' }}>
                {error}
              </div>
            )}

            <div className="form-group">
              <label className="form-label">Document Title</label>
              <input
                type="text"
                required
                className="form-input"
                placeholder="e.g. Master Services Agreement v2"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
              />
            </div>

            <div className="form-group">
              <label className="form-label">Description / Legal Notes</label>
              <textarea
                className="form-textarea"
                rows={2}
                placeholder="Confidential terms, clauses, or client notes..."
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            </div>

            <div className="form-group">
              <label className="form-label">Select File (PDF, DOCX, TXT, etc.)</label>
              <input
                type="file"
                required
                className="form-input"
                onChange={(e) => setFile(e.target.files[0] || null)}
              />
              {file && (
                <div style={{ marginTop: '0.4rem', fontSize: '0.775rem', color: '#64748b' }}>
                  Selected: <strong>{file.name}</strong> ({(file.size / 1024).toFixed(1)} KB)
                </div>
              )}
            </div>

            {encrypting && (
              <div className="alert alert-warning" style={{ fontSize: '0.8rem' }}>
                <RefreshCw className="animate-spin" size={16} />
                <span>Performing AES-256-GCM encryption & generating cryptographic nonce...</span>
              </div>
            )}
          </div>

          <div className="modal-footer">
            <button
              type="button"
              onClick={onClose}
              disabled={encrypting}
              className="btn btn-outline"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={encrypting}
              className="btn btn-primary"
            >
              {encrypting ? <RefreshCw className="animate-spin" size={16} /> : <Upload size={16} />}
              <span>Encrypt & Store</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
