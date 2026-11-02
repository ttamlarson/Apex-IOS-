/*! apex-security.js — data-safety helpers for Apex Protocol (no dependencies)
 *
 * What it gives you
 *  - Apex.esc(text)            HTML-escape anything before it goes into innerHTML
 *  - Apex.validateBackup(text) safe JSON parsing + sanitising for ANY import path
 *  - Encrypted export/import   AES-256-GCM, key from password via PBKDF2 (Web Crypto)
 *  - Safety copy before every import + Undo
 *  - Native iOS (Capacitor) file saving via Filesystem + Share plugins
 *  - Asks the browser for persistent storage and warns if storage is unavailable
 */
(function (global) {
  'use strict';

  const LIMITS = { bytes: 5 * 1024 * 1024, nodes: 250000, depth: 12, str: 2000 };
  const PRE_KEY = 'apex_pre_import_backup';
  const KEY_RE = /^[A-Za-z0-9_.:\-]{1,80}$/;
  const BAD_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
  const CTRL_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g;
  const PBKDF2_ITER = 310000;

  /* ---------- escaping ---------- */
  const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;' };
  function esc(v) {
    return String(v === null || v === undefined ? '' : v).replace(/[&<>"'`]/g, (c) => ESC[c]);
  }

  /* ---------- sanitising / validation ---------- */
  function clean(value, state, depth) {
    if (++state.n > LIMITS.nodes) throw new Error('Backup is too large or complex.');
    if (depth > LIMITS.depth) throw new Error('Backup is nested too deeply.');
    if (value === null || typeof value === 'boolean') return value;
    if (typeof value === 'number') {
      if (!Number.isFinite(value)) throw new Error('Backup contains an invalid number.');
      return value;
    }
    if (typeof value === 'string') return value.replace(CTRL_RE, '').slice(0, LIMITS.str);
    if (Array.isArray(value)) return value.map((v) => clean(v, state, depth + 1));
    if (typeof value === 'object') {
      const out = {};
      for (const k of Object.keys(value)) {
        if (BAD_KEYS.has(k)) continue; // blocks prototype pollution
        out[k] = clean(value[k], state, depth + 1);
      }
      return out;
    }
    throw new Error('Backup contains an unsupported value.');
  }

  /** Parse and sanitise backup text. Use this in your existing import handler too.
   *  opts.allowedKeys: optional array; unknown top-level keys are dropped. */
  function validateBackup(text, opts) {
    opts = opts || {};
    if (typeof text !== 'string') throw new Error('Backup must be text.');
    if (new Blob([text]).size > LIMITS.bytes) throw new Error('Backup file is too large.');
    let parsed;
    try { parsed = JSON.parse(text); } catch (e) { throw new Error('That file is not valid JSON.'); }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('Unexpected backup format.');
    }
    const cleaned = clean(parsed, { n: 0 }, 0);
    if (opts.allowedKeys) {
      for (const k of Object.keys(cleaned)) if (opts.allowedKeys.indexOf(k) < 0) delete cleaned[k];
    }
    return cleaned;
  }

  /* ---------- localStorage snapshot / restore ---------- */
  function snapshot() {
    const out = {};
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k === PRE_KEY || k.indexOf('__apex_') === 0) continue;
      out[k] = localStorage.getItem(k);
    }
    return out;
  }

  function toEnvelope(raw) {
    const data = {};
    for (const k of Object.keys(raw)) {
      try { data[k] = { j: JSON.parse(raw[k]) }; } catch (e) { data[k] = { s: raw[k] }; }
    }
    return data;
  }

  function restoreRaw(raw) {
    localStorage.clear();
    for (const k of Object.keys(raw)) localStorage.setItem(k, raw[k]);
  }

  function savePreImportCopy() {
    try {
      localStorage.setItem(PRE_KEY, JSON.stringify({ savedAt: new Date().toISOString(), data: snapshot() }));
    } catch (e) { /* quota: carry on, user already confirmed */ }
  }

  function applyData(data) {
    const before = snapshot();
    savePreImportCopy();
    const keep = localStorage.getItem(PRE_KEY);
    try {
      localStorage.clear();
      if (keep) localStorage.setItem(PRE_KEY, keep);
      for (const k of Object.keys(data)) {
        if (!KEY_RE.test(k) || BAD_KEYS.has(k)) continue;
        const e = data[k];
        if (!e || typeof e !== 'object') continue;
        if ('j' in e) localStorage.setItem(k, JSON.stringify(e.j));
        else if (typeof e.s === 'string') localStorage.setItem(k, e.s);
      }
    } catch (err) {
      restoreRaw(before); // never leave the user half-imported
      throw new Error('Import failed, your previous data was restored.');
    }
  }

  function undoLastImport() {
    const raw = localStorage.getItem(PRE_KEY);
    if (!raw) throw new Error('No safety copy found.');
    const saved = JSON.parse(raw).data;
    restoreRaw(saved);
  }

  /* ---------- encryption (AES-GCM + PBKDF2) ---------- */
  function toB64(bytes) {
    let s = '';
    const CH = 0x8000;
    for (let i = 0; i < bytes.length; i += CH) s += String.fromCharCode.apply(null, bytes.subarray(i, i + CH));
    return btoa(s);
  }
  function fromB64(b64) {
    const s = atob(b64);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }
  function needCrypto() {
    if (!global.crypto || !global.crypto.subtle) throw new Error('Encryption is not available in this context.');
  }
  async function deriveKey(password, salt, usage) {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: salt, iterations: PBKDF2_ITER, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, usage
    );
  }
  async function encryptText(plain, password) {
    needCrypto();
    if (!password || password.length < 8) throw new Error('Use a password of at least 8 characters.');
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(password, salt, ['encrypt']);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, new TextEncoder().encode(plain)));
    return JSON.stringify({ apexEncrypted: 1, kdf: 'PBKDF2-SHA256', salt: toB64(salt), iv: toB64(iv), data: toB64(ct) });
  }
  async function decryptText(text, password) {
    needCrypto();
    let o;
    try { o = JSON.parse(text); } catch (e) { throw new Error('Not a valid encrypted backup.'); }
    if (!o || o.apexEncrypted !== 1) throw new Error('Not an Apex encrypted backup.');
    try {
      const key = await deriveKey(password, fromB64(o.salt), ['decrypt']);
      const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(o.iv) }, key, fromB64(o.data));
      return new TextDecoder().decode(pt);
    } catch (e) {
      throw new Error('Wrong password or the file is damaged.');
    }
  }
  function isEncrypted(text) {
    try { return JSON.parse(text).apexEncrypted === 1; } catch (e) { return false; }
  }

  /* ---------- file saving (browser or native iOS) ---------- */
  async function saveFile(name, text) {
    const C = global.Capacitor;
    if (C && C.isNativePlatform && C.isNativePlatform()) {
      const P = C.Plugins || {};
      if (!P.Filesystem || !P.Share) {
        throw new Error('Install @capacitor/filesystem and @capacitor/share, then rebuild the app.');
      }
      const r = await P.Filesystem.writeFile({ path: name, data: text, directory: 'CACHE', encoding: 'utf8' });
      await P.Share.share({ title: name, url: r.uri });
      return;
    }
    const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
    const a = document.createElement('a');
    a.href = url; a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }

  /* ---------- small password dialog ---------- */
  function askPassword(message, confirmToo) {
    return new Promise((resolve) => {
      const overlay = document.createElement('div');
      overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center;z-index:99999;padding:16px';
      const box = document.createElement('div');
      box.style.cssText = 'background:#14161a;color:#f2f3f5;border:1px solid #2a2d33;border-radius:12px;padding:18px;max-width:340px;width:100%;font:15px system-ui,sans-serif';
      const p = document.createElement('p');
      p.style.margin = '0 0 12px';
      p.textContent = message;
      const fieldCss = 'width:100%;box-sizing:border-box;padding:10px;border-radius:8px;border:1px solid #2a2d33;background:#0b0c0e;color:inherit;font-size:16px';
      const i1 = document.createElement('input');
      i1.type = 'password'; i1.autocomplete = 'off'; i1.style.cssText = fieldCss; i1.placeholder = 'Password';
      let i2 = null;
      if (confirmToo) {
        i2 = document.createElement('input');
        i2.type = 'password'; i2.autocomplete = 'off'; i2.style.cssText = fieldCss + ';margin-top:8px'; i2.placeholder = 'Repeat password';
      }
      const row = document.createElement('div');
      row.style.cssText = 'display:flex;gap:8px;justify-content:flex-end;margin-top:14px';
      const mk = (label) => {
        const b = document.createElement('button');
        b.type = 'button'; b.textContent = label;
        b.style.cssText = 'padding:9px 14px;border-radius:8px;border:1px solid #2a2d33;background:#1d2026;color:inherit;font-size:15px';
        return b;
      };
      const cancel = mk('Cancel'), ok = mk('OK');
      const done = (v) => { overlay.remove(); resolve(v); };
      cancel.onclick = () => done(null);
      ok.onclick = () => {
        if (confirmToo) {
          if (i1.value.length < 8) { p.textContent = 'Use at least 8 characters.'; return; }
          if (i1.value !== i2.value) { p.textContent = 'Passwords do not match.'; return; }
        }
        done(i1.value || null);
      };
      row.append(cancel, ok);
      box.append(p, i1);
      if (i2) box.append(i2);
      box.append(row);
      overlay.append(box);
      document.body.append(overlay);
      i1.focus();
    });
  }

  /* ---------- user flows ---------- */
  async function exportEncrypted() {
    try {
      const pw = await askPassword('Choose a password for this backup. If you forget it, the backup cannot be opened.', true);
      if (!pw) return;
      const payload = JSON.stringify({
        app: 'apex-protocol', version: 1, exportedAt: new Date().toISOString(), data: toEnvelope(snapshot())
      });
      const text = await encryptText(payload, pw);
      await saveFile('apex-backup-' + new Date().toISOString().slice(0, 10) + '.apexbackup.json', text);
    } catch (e) { alert(e.message || 'Export failed.'); }
  }

  function pickFile() {
    return new Promise((resolve) => {
      const i = document.createElement('input');
      i.type = 'file'; i.accept = '.json,application/json';
      i.onchange = () => resolve((i.files && i.files[0]) || null);
      i.click();
    });
  }

  async function importEncrypted() {
    try {
      const file = await pickFile();
      if (!file) return;
      if (file.size > LIMITS.bytes) throw new Error('That file is too large.');
      let text = await file.text();
      if (isEncrypted(text)) {
        const pw = await askPassword('Enter the backup password.', false);
        if (!pw) return;
        text = await decryptText(text, pw);
      }
      const obj = validateBackup(text);
      if (obj.app !== 'apex-protocol' || !obj.data || typeof obj.data !== 'object') {
        throw new Error('This is not an Apex Protocol backup made with the encrypted export.');
      }
      if (!global.confirm('Replace ALL current records with this backup? A safety copy of your current data is saved first.')) return;
      applyData(obj.data);
      alert('Backup restored. The app will reload.');
      location.reload();
    } catch (e) { alert(e.message || 'Import failed.'); }
  }

  function undoImport() {
    try {
      if (!global.confirm('Restore the data you had before the last import?')) return;
      undoLastImport();
      alert('Previous data restored. The app will reload.');
      location.reload();
    } catch (e) { alert(e.message); }
  }

  /* ---------- UI injection (next to your existing Export button) ---------- */
  function injectUI() {
    const exportBtn = Array.prototype.find.call(document.querySelectorAll('button'), (b) => /export json backup/i.test(b.textContent));
    if (!exportBtn || !exportBtn.parentElement) return;
    const wrap = document.createElement('div');
    wrap.style.cssText = 'display:flex;gap:8px;flex-wrap:wrap;margin-top:10px';
    [['Export encrypted backup', exportEncrypted], ['Import encrypted backup', importEncrypted], ['Undo last import', undoImport]]
      .forEach(([label, fn]) => {
        const b = document.createElement('button');
        b.type = 'button'; b.className = exportBtn.className; b.textContent = label;
        b.addEventListener('click', fn);
        wrap.append(b);
      });
    exportBtn.parentElement.parentNode.insertBefore(wrap, exportBtn.parentElement.nextSibling);
  }

  function storageWorks() {
    try { localStorage.setItem('__apex_t', '1'); localStorage.removeItem('__apex_t'); return true; } catch (e) { return false; }
  }

  function init() {
    if (navigator.storage && navigator.storage.persist) navigator.storage.persist().catch(() => {});
    if (!storageWorks()) {
      const d = document.createElement('div');
      d.textContent = 'Storage is unavailable (private mode or blocked). Your records will NOT be saved.';
      d.style.cssText = 'position:fixed;left:0;right:0;top:0;padding:10px;background:#8a1c1c;color:#fff;font:14px system-ui,sans-serif;z-index:99998;text-align:center';
      document.body.append(d);
    }
    injectUI();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();

  global.Apex = Object.freeze({
    esc, validateBackup, snapshot, encryptText, decryptText, isEncrypted,
    exportEncrypted, importEncrypted, undoLastImport, savePreImportCopy
  });
})(window);
