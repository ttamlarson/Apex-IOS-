(() => {
  const cap = window.Capacitor;
  const LN = cap && cap.Plugins && cap.Plugins.LocalNotifications;
  if (!cap || !cap.isNativePlatform || !cap.isNativePlatform() || !LN) return;

  const NOTIF_ID = 1001;
  const remaining = () => {
    const [m, s] = document.getElementById('timer').textContent.split(':').map(Number);
    return m * 60 + s;
  };
  const cancelRest = async () => {
    try { await LN.cancel({ notifications: [{ id: NOTIF_ID }] }); } catch (e) {}
  };
  const scheduleRest = async seconds => {
    try {
      await cancelRest();
      let perm = await LN.checkPermissions();
      if (perm.display !== 'granted') perm = await LN.requestPermissions();
      if (perm.display !== 'granted') return;
      await LN.schedule({
        notifications: [{
          id: NOTIF_ID,
          title: 'Rest complete',
          body: 'Time for your next set.',
          schedule: { at: new Date(Date.now() + seconds * 1000) }
        }]
      });
    } catch (e) { console.warn('Rest notification failed', e); }
  };

  document.addEventListener('click', e => {
    const b = e.target.closest('button');
    if (!b) return;
    if (b.id === 'starttimer' || b.hasAttribute('data-rest')) {
      const s = remaining();
      if (s > 0) scheduleRest(s);
    } else if (b.id === 'pausetimer' || b.id === 'resettimer' || b.hasAttribute('data-seconds')) {
      cancelRest();
    }
  });
})();
