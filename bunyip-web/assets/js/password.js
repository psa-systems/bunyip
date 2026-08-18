// Password UX for the auth pages (BUNYIP-240 live validation + HIBP breach
// check, BUNYIP-282 show/hide toggle). Loaded with `defer` by the pages that
// render the signup / reset password cards.
//
// BUNYIP-424: extracted from the `password_live_validation_script()` and
// `password_toggle_script()` inline <script> blocks in handlers::auth_pages so
// script-src can be 'self' with no 'unsafe-inline'.
//
// Both halves are idempotent: they attach listeners only once per element, so a
// second render (e.g. a future htmx swap) does not double-bind. Graceful
// degradation: with no JS the static rules list still renders and the
// server-side `password_ok()` remains the final backstop.
(function () {
  var pw = document.getElementById('password');
  var cf = document.getElementById('confirm');
  if (!pw || pw.dataset.pwInit === '1') return;
  pw.dataset.pwInit = '1';

  // Tailwind utility classes for the three visual states. The leading
  // indicator glyph + the row text color flip together so the row reads as
  // pass/fail at a glance. BUNYIP-554: the three glyphs are pre-rendered inline
  // SVGs (handlers::auth_pages::pw_state_glyphs); the `pw-<state>` class this
  // sets is what input.css uses to reveal the matching one, so no markup is
  // built here.
  var STATES = {
    pending: { cls: 'text-muted-foreground' },
    pass:    { cls: 'text-teal-600 dark:text-teal-400' },
    fail:    { cls: 'text-destructive' }
  };
  // BUNYIP-250: when a row carries data-label-{pass,fail,pending}, the visible
  // label flips per state. The breach row uses this so a ✗ stops appearing next
  // to the contradictory "Not found in a known data breach" copy.
  function syncRowLabel(row, state) {
    if (!row) return;
    var lbl = row.querySelector('.pw-label');
    if (!lbl) return;
    var key = 'label' + state.charAt(0).toUpperCase() + state.slice(1);
    var next = row.dataset[key];
    if (typeof next === 'string' && next.length > 0) lbl.textContent = next;
  }
  function setState(row, state) {
    if (!row) return;
    var s = STATES[state];
    row.className = (row.className || '')
      .replace(/\b(text-muted-foreground|text-teal-600|dark:text-teal-400|text-destructive|pw-pending|pw-pass|pw-fail)\b/g, '')
      .trim() + ' pw-' + state + ' ' + s.cls;
    syncRowLabel(row, state);
    // BUNYIP-250: the breach row carries a follow-up help paragraph
    // (#pw-breach-help) that explains what to do; surface it only when the row
    // is in `fail` so the help text never falsely warns the user.
    if (row.id === 'pw-breach') {
      var help = document.getElementById('pw-breach-help');
      if (help) help.hidden = state !== 'fail';
    }
  }
  function rowState(row) {
    if (!row) return 'pending';
    if (row.classList.contains('pw-pass')) return 'pass';
    if (row.classList.contains('pw-fail')) return 'fail';
    return 'pending';
  }

  var rowLen    = document.getElementById('pw-len');
  var rowCase   = document.getElementById('pw-case');
  var rowDigit  = document.getElementById('pw-digit');
  var rowBreach = document.getElementById('pw-breach');
  var submit    = pw.form ? pw.form.querySelector('button[type="submit"]') : null;
  var confirmMsg = document.getElementById('pw-confirm-msg');

  // Mirror the server-side `password_ok()` rules verbatim (handlers/mod.rs).
  function checkLocal(v) {
    setState(rowLen,   v.length >= 12 ? 'pass' : (v.length > 0 ? 'fail' : 'pending'));
    var hasLower = /[a-z]/.test(v);
    var hasUpper = /[A-Z]/.test(v);
    setState(rowCase,  (hasLower && hasUpper) ? 'pass' : (v.length > 0 ? 'fail' : 'pending'));
    var hasDigit   = /\d/.test(v);
    var hasSpecial = /[^A-Za-z0-9]/.test(v);
    setState(rowDigit, (hasDigit && hasSpecial) ? 'pass' : (v.length > 0 ? 'fail' : 'pending'));
  }

  // HaveIBeenPwned k-anonymity: SHA-1 client-side, send only the first 5 hex
  // chars to api.pwnedpasswords.com/range/{prefix}, scan the returned list for
  // the matching 35-char suffix. The full password never leaves the browser.
  // https://haveibeenpwned.com/API/v3#PwnedPasswords
  function bytesToHex(bytes) {
    var out = '';
    for (var i = 0; i < bytes.length; i++) {
      var h = bytes[i].toString(16);
      out += h.length === 1 ? '0' + h : h;
    }
    return out.toUpperCase();
  }
  async function checkBreach(v) {
    if (!v || !window.crypto || !window.crypto.subtle) {
      setState(rowBreach, 'pending');
      refreshSubmit();
      return;
    }
    try {
      var enc = new TextEncoder().encode(v);
      var hashBuf = await window.crypto.subtle.digest('SHA-1', enc);
      var hash = bytesToHex(new Uint8Array(hashBuf));
      var prefix = hash.slice(0, 5);
      var suffix = hash.slice(5);
      var resp = await fetch('https://api.pwnedpasswords.com/range/' + prefix);
      if (!resp.ok) {
        // Network / API hiccup is non-fatal; leave the row pending so the user
        // isn't blocked on an outage.
        setState(rowBreach, 'pending');
        refreshSubmit();
        return;
      }
      var body = await resp.text();
      var lines = body.split(/\r?\n/);
      var seen = false;
      for (var i = 0; i < lines.length; i++) {
        var s = lines[i].split(':')[0];
        if (s && s.toUpperCase() === suffix) { seen = true; break; }
      }
      setState(rowBreach, seen ? 'fail' : 'pass');
      // BUNYIP-283: refresh the submit gate so the button flips state when the
      // breach result lands. The input-event refresh ran 500 ms ago with
      // rowBreach=pending; without this call, a clean password that resolved to
      // pass leaves the gate computed against the stale pending state and the
      // button stays disabled.
      refreshSubmit();
    } catch (_e) {
      setState(rowBreach, 'pending');
      refreshSubmit();
    }
  }

  // Debounce the breach check: avoid hammering HIBP on every keystroke. The
  // local rules update immediately; the breach check waits for 500ms of
  // typing-silence.
  var breachTimer = null;
  function scheduleBreach(v) {
    if (breachTimer) clearTimeout(breachTimer);
    if (!v) { setState(rowBreach, 'pending'); return; }
    setState(rowBreach, 'pending');
    breachTimer = setTimeout(function () { checkBreach(v); }, 500);
  }

  function refreshSubmit() {
    if (!submit) return;
    var all = ['pw-len','pw-case','pw-digit','pw-breach']
      .map(function (id) { return document.getElementById(id); })
      .every(function (r) { return rowState(r) === 'pass'; });
    var match = cf && cf.value.length > 0 && cf.value === pw.value;
    submit.disabled = !(all && match);
  }
  function refreshConfirm() {
    if (!cf || !confirmMsg) return;
    if (cf.value.length === 0) {
      confirmMsg.textContent = '';
      confirmMsg.className = 'text-xs mt-1';
      return;
    }
    if (cf.value === pw.value) {
      confirmMsg.textContent = '✓ Passwords match';
      confirmMsg.className = 'text-xs mt-1 text-teal-600 dark:text-teal-400';
    } else {
      confirmMsg.textContent = '✗ Passwords do not match';
      confirmMsg.className = 'text-xs mt-1 text-destructive';
    }
  }

  pw.addEventListener('input', function () {
    checkLocal(pw.value);
    scheduleBreach(pw.value);
    refreshConfirm();
    refreshSubmit();
  });
  if (cf) {
    cf.addEventListener('input', function () {
      refreshConfirm();
      refreshSubmit();
    });
  }
  // Initial pass so a value preserved across a server re-render (BUNYIP-240
  // preserves the typed password on rejection) immediately reflects state.
  if (pw.value) {
    checkLocal(pw.value);
    scheduleBreach(pw.value);
  }
  refreshConfirm();
  refreshSubmit();
})();

// BUNYIP-282: every [data-pw-toggle] button flips its target input's `type`
// between password and text and updates aria-pressed + aria-label so the reveal
// state is announced. BUNYIP-554: both eye glyphs are pre-rendered inline SVGs
// and input.css picks one off `aria-pressed`, so nothing is swapped here.
(function () {
  var buttons = document.querySelectorAll('[data-pw-toggle]');
  buttons.forEach(function (btn) {
    if (btn.dataset.pwToggleInit === '1') return;
    btn.dataset.pwToggleInit = '1';
    var targetId = btn.getAttribute('data-pw-toggle');
    var input = document.getElementById(targetId);
    if (!input) return;
    btn.addEventListener('click', function () {
      var revealed = input.type === 'text';
      input.type = revealed ? 'password' : 'text';
      btn.setAttribute('aria-pressed', revealed ? 'false' : 'true');
      btn.setAttribute('aria-label', revealed ? 'Show password' : 'Hide password');
    });
  });
})();
