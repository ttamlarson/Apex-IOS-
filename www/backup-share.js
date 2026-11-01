(() => {
  const cap = window.Capacitor;
  const P = cap && cap.Plugins;
  if (!cap || !cap.isNativePlatform || !cap.isNativePlatform() || !P || !P.Filesystem || !P.Share) return;

  document.addEventListener('click', async e => {
    if (!e.target.closest('#export')) return;
    e.preventDefault();
    e.stopImmediatePropagation();
    try {
      const raw = localStorage.getItem('apexProtocolData_v1') || '{}';
      const data = JSON.stringify({ app: 'Apex Protocol', ...JSON.parse(raw) }, null, 2);
      const d = new Date();
      const stamp = d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
      const path = 'apex-protocol-backup-' + stamp + '.json';
      await P.Filesystem.writeFile({ path, data, directory: 'CACHE', encoding: 'utf8' });
      const res = await P.Filesystem.getUri({ path, directory: 'CACHE' });
      await P.Share.share({ title: 'Apex Protocol backup', url: res.uri });
    } catch (err) {
      const msg = String((err && err.message) || err);
      if (!/cancel/i.test(msg)) alert('Backup failed: ' + msg);
    }
  }, true);
})();
