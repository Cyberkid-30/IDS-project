import { useState } from 'react';

const PROTOCOLS = ['any', 'tcp', 'udp', 'icmp'];
const SEVERITIES = ['low', 'medium', 'high', 'critical'];

const EMPTY = {
  name: '',
  description: '',
  protocol: 'any',
  source_ip: '',
  source_port: '',
  dest_ip: '',
  dest_port: '',
  pattern: '',
  severity: 'medium',
  enabled: true,
  category: '',
  reference: '',
};

export default function SignatureForm({ initial, onSubmit, onCancel }) {
  const [form, setForm] = useState(() => ({ ...EMPTY, ...(initial || {}) }));
  const [error, setError] = useState(null);
  const [saving, setSaving] = useState(false);

  function set(field, value) {
    setForm((f) => ({ ...f, [field]: value }));
  }

  function toNullable(v) {
    return v === '' ? null : v;
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setSaving(true);
    setError(null);
    try {
      await onSubmit({
        ...form,
        description: toNullable(form.description),
        source_ip: toNullable(form.source_ip),
        source_port: toNullable(form.source_port),
        dest_ip: toNullable(form.dest_ip),
        dest_port: toNullable(form.dest_port),
        pattern: toNullable(form.pattern),
        category: toNullable(form.category),
        reference: toNullable(form.reference),
      });
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <form onSubmit={handleSubmit}>
      <div className="form-grid">
        <div className="field form-grid--full">
          <label className="field__label">Name</label>
          <input
            className="input"
            required
            maxLength={255}
            value={form.name}
            onChange={(e) => set('name', e.target.value)}
            placeholder="e.g. SQL Injection Attempt"
          />
        </div>

        <div className="field form-grid--full">
          <label className="field__label">Description</label>
          <textarea
            className="textarea"
            maxLength={1000}
            value={form.description || ''}
            onChange={(e) => set('description', e.target.value)}
            placeholder="What does this signature detect, and why does it matter?"
            style={{ fontFamily: 'var(--font-sans)', minHeight: 56 }}
          />
        </div>

        <div className="field">
          <label className="field__label">Protocol</label>
          <select className="select" value={form.protocol} onChange={(e) => set('protocol', e.target.value)}>
            {PROTOCOLS.map((p) => <option key={p} value={p}>{p.toUpperCase()}</option>)}
          </select>
        </div>

        <div className="field">
          <label className="field__label">Severity</label>
          <select className="select" value={form.severity} onChange={(e) => set('severity', e.target.value)}>
            {SEVERITIES.map((s) => <option key={s} value={s}>{s[0].toUpperCase() + s.slice(1)}</option>)}
          </select>
        </div>

        <div className="field">
          <label className="field__label">Source IP / CIDR</label>
          <input className="input mono" value={form.source_ip || ''} onChange={(e) => set('source_ip', e.target.value)} placeholder="any" />
        </div>

        <div className="field">
          <label className="field__label">Source port</label>
          <input className="input mono" value={form.source_port || ''} onChange={(e) => set('source_port', e.target.value)} placeholder="any" />
        </div>

        <div className="field">
          <label className="field__label">Destination IP / CIDR</label>
          <input className="input mono" value={form.dest_ip || ''} onChange={(e) => set('dest_ip', e.target.value)} placeholder="any" />
        </div>

        <div className="field">
          <label className="field__label">Destination port</label>
          <input className="input mono" value={form.dest_port || ''} onChange={(e) => set('dest_port', e.target.value)} placeholder="e.g. 22, 80, 1-1024" />
        </div>

        <div className="field form-grid--full">
          <label className="field__label">Payload pattern (regex)</label>
          <textarea
            className="textarea"
            value={form.pattern || ''}
            onChange={(e) => set('pattern', e.target.value)}
            placeholder="Leave blank to match on header fields only"
          />
          <span className="field__hint">Matched against decoded packet payload. Must be a valid regular expression.</span>
        </div>

        <div className="field">
          <label className="field__label">Category</label>
          <input className="input" value={form.category || ''} onChange={(e) => set('category', e.target.value)} placeholder="e.g. recon, exploit, malware" />
        </div>

        <div className="field">
          <label className="field__label">Reference</label>
          <input className="input" value={form.reference || ''} onChange={(e) => set('reference', e.target.value)} placeholder="CVE-XXXX-XXXXX or URL" />
        </div>

        <div className="field form-grid--full" style={{ flexDirection: 'row', alignItems: 'center', gap: 8 }}>
          <input
            type="checkbox"
            id="enabled"
            checked={form.enabled}
            onChange={(e) => set('enabled', e.target.checked)}
            style={{ width: 16, height: 16 }}
          />
          <label htmlFor="enabled" className="field__label" style={{ textTransform: 'none' }}>
            Signature is active
          </label>
        </div>
      </div>

      {error && <div className="field__error" style={{ marginTop: 12 }}>{error}</div>}

      <div className="form-actions">
        <button type="button" className="btn btn--ghost" onClick={onCancel} disabled={saving}>Cancel</button>
        <button type="submit" className="btn btn--primary" disabled={saving}>
          {saving ? 'Saving…' : initial ? 'Save changes' : 'Create signature'}
        </button>
      </div>
    </form>
  );
}
