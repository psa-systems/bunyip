// Theme flash prevention plus the theme / high-contrast toggles (BUNYIP-424:
// extracted from the inline <script> blocks in views::layout so script-src can
// be 'self' with no 'unsafe-inline').
//
// Loaded synchronously (NOT deferred) from the document head: the stored theme
// has to land on <html> before first paint or the page flashes the wrong theme.
// The toggle buttons are wired with one delegated click listener on
// [data-theme-toggle] / [data-contrast-toggle], replacing the old onclick=.
(function () {
  var KEY = 'theme-storage';

  // BUNYIP-613: a suppressed failure still has to be visible somewhere. Guarded
  // so a console-less environment does not throw inside the handler.
  function report(level, what, e) {
    if (window.console && console[level]) console[level]('bunyip: ' + what, e || '');
  }

  function read() {
    try {
      var raw = localStorage.getItem(KEY);
      if (raw) return JSON.parse(raw).state || {};
    } catch (e) {
      // Storage blocked or the stored value is corrupt: fall back to `system`.
      report('warn', 'stored theme could not be read; falling back to the system theme', e);
    }
    return {};
  }

  function save(theme, highContrast) {
    try {
      localStorage.setItem(
        KEY,
        JSON.stringify({ state: { theme: theme, highContrast: highContrast }, version: 0 })
      );
    } catch (e) {
      // The toggle still applies to this page; only persistence is lost.
      report('warn', 'theme choice could not be saved; it will not survive a reload', e);
    }
  }

  try {
    var root = document.documentElement;
    var stored = read();
    var theme = stored.theme || 'system';
    var dark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    root.classList.add(theme === 'system' ? (dark ? 'dark' : 'light') : theme);
    if (stored.highContrast) root.classList.add('high-contrast');
  } catch (e) {
    // This runs before first paint, so throwing would leave the document
    // unstyled. Carry on in the default theme and say what was lost.
    report('error', 'theme could not be applied; the page renders in the default theme', e);
  }

  function toggleTheme() {
    var root = document.documentElement;
    var next = root.classList.contains('dark') ? 'light' : 'dark';
    root.classList.remove('light', 'dark');
    root.classList.add(next);
    save(next, root.classList.contains('high-contrast'));
  }

  function toggleContrast() {
    var on = document.documentElement.classList.toggle('high-contrast');
    save(read().theme || 'system', on);
  }

  document.addEventListener('click', function (e) {
    var el = e.target;
    if (!el || typeof el.closest !== 'function') return;
    if (el.closest('[data-theme-toggle]')) {
      toggleTheme();
      return;
    }
    if (el.closest('[data-contrast-toggle]')) toggleContrast();
  });
})();
