// Shared client-side behaviour for every SSR page (BUNYIP-424).
//
// Everything here used to ship as inline <script> blocks in views::layout and as
// on* attributes on individual elements. Both are blocked by a CSP without
// script-src 'unsafe-inline', so the code moved into this file and the elements
// now opt in through data-* attributes handled by delegated listeners:
//
//   [data-confirm]       form  - window.confirm() gate before submit
//   [data-copy]          button- copy the attribute value to the clipboard
//   [data-dialog-open]   button- showModal() the <dialog> with that id
//   [data-dialog-close]  button- close the enclosing <dialog>
//   [data-feedback-link] a     - append the current path as ?from=
//   [data-redirect-to]   any   - navigate after [data-redirect-after] ms
//   [data-reload-after]  any   - reload after that many ms
//   [data-sensitive-toggle] button - toggle the blur on the enclosing [data-sensitive]
//
// Loaded with `defer` from the document head, so the DOM is parsed before it
// runs and every listener below is registered once per page load.
(function () {
  // ---------------------------------------------------------------- toasts --
  // Tiny toast system mounted in every <body>. `kind` is
  // "success" | "error" | "info" (default "info"); each call appends an
  // auto-dismissing pill into #bunyip-toast-root. BUNYIP-98: the column is
  // capped at 5 visible pills, evicting the oldest, so rapid-fire calls (e.g.
  // spamming a Copy button) cannot grow it without bound. The auto-dismiss
  // timers guard on pill.parentNode so an evicted pill never double-removes.
  window.bunyipToast = function (msg, kind) {
    var root = document.getElementById('bunyip-toast-root');
    if (!root) return;
    while (root.children.length >= 5) root.removeChild(root.firstChild);
    var palette =
      {
        success: 'bg-emerald-600 text-white',
        error: 'bg-red-600 text-white',
        info: 'bg-slate-800 text-white',
      }[kind || 'info'] || 'bg-slate-800 text-white';
    var pill = document.createElement('div');
    pill.className = 'pointer-events-auto rounded-md px-4 py-2 text-sm shadow-lg ' + palette;
    pill.setAttribute('role', 'status');
    pill.textContent = msg;
    pill.style.transition = 'opacity 200ms ease, transform 200ms ease';
    pill.style.opacity = '0';
    pill.style.transform = 'translateY(-8px)';
    root.appendChild(pill);
    requestAnimationFrame(function () {
      pill.style.opacity = '1';
      pill.style.transform = 'translateY(0)';
    });
    setTimeout(function () {
      pill.style.opacity = '0';
      pill.style.transform = 'translateY(-8px)';
      setTimeout(function () {
        if (pill.parentNode) pill.parentNode.removeChild(pill);
      }, 250);
    }, 2500);
  };

  // Drain ?toast_ok= / ?toast_err= so a handler can surface a confirmation via
  // a 302 (`Location: /settings?toast_ok=Email%20updated`). The params are
  // stripped with history.replaceState so a reload does not re-fire the toast.
  try {
    var url = new URL(window.location.href);
    var ok = url.searchParams.get('toast_ok');
    var err = url.searchParams.get('toast_err');
    if (ok || err) {
      url.searchParams.delete('toast_ok');
      url.searchParams.delete('toast_err');
      history.replaceState(null, '', url.pathname + (url.search || '') + url.hash);
      if (ok) window.bunyipToast(ok, 'success');
      if (err) window.bunyipToast(err, 'error');
    }
  } catch (e) {}

  // ------------------------------------------------------- OTP autosubmit --
  // BUNYIP-331: submit a 2FA form the moment its six-digit TOTP field is
  // complete. The exact ^[0-9]{6}$ gate never matches a dashed XXXX-XXXX
  // recovery code; checkValidity() keeps multi-field forms from half-submitting;
  // the per-form flag guards a double submit while navigation is in flight.
  var OTP = /^[0-9]{6}$/;
  document.addEventListener('input', function (e) {
    var el = e.target;
    if (!el || typeof el.matches !== 'function' || !el.matches('input[data-otp-autosubmit]')) return;
    if (!OTP.test(el.value)) return;
    var form = el.form;
    if (!form || form.dataset.otpSubmitting === '1') return;
    if (typeof form.checkValidity === 'function' && !form.checkValidity()) return;
    form.dataset.otpSubmitting = '1';
    if (typeof form.requestSubmit === 'function') form.requestSubmit();
    else form.submit();
  });

  // -------------------------------------------------------- profile menus --
  // BUNYIP-408: close an open <details data-menu> on click-away or Escape.
  document.addEventListener('click', function (e) {
    document.querySelectorAll('details[data-menu][open]').forEach(function (d) {
      if (!d.contains(e.target)) d.removeAttribute('open');
    });
  });
  document.addEventListener('keydown', function (e) {
    if (e.key !== 'Escape') return;
    document.querySelectorAll('details[data-menu][open]').forEach(function (d) {
      d.removeAttribute('open');
    });
  });

  // ------------------------------------------------------ confirm-on-submit --
  // Destructive forms carry data-confirm="<question>"; cancelling stops the
  // submit exactly like the old `onsubmit="return confirm(...)"` did.
  document.addEventListener(
    'submit',
    function (e) {
      var form = e.target;
      if (!form || typeof form.getAttribute !== 'function') return;
      var question = form.getAttribute('data-confirm');
      if (!question) return;
      if (!window.confirm(question)) e.preventDefault();
    },
    true
  );

  // ---------------------------------------------------- copy-to-clipboard --
  // The command text lives in the button's own data-copy attribute, so no
  // API-sourced value is ever executable. The Clipboard API needs a secure
  // context; without it, select the preceding <code>/<pre> so the user can copy
  // manually. Feedback lands both on the button label and as a toast.
  document.addEventListener('click', function (e) {
    var el = e.target;
    if (!el || typeof el.closest !== 'function') return;
    var btn = el.closest('[data-copy]');
    if (!btn) return;
    var label = btn.innerText;
    var text = btn.getAttribute('data-copy');
    function restore(msg, ms) {
      btn.innerText = msg;
      setTimeout(function () {
        btn.innerText = label;
      }, ms);
    }
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text).then(
        function () {
          restore('Copied', 1500);
          if (window.bunyipToast) window.bunyipToast('Copied to clipboard', 'success');
        },
        function () {
          restore('Copy failed', 1500);
          if (window.bunyipToast) window.bunyipToast('Copy failed', 'error');
        }
      );
    } else {
      window.getSelection().selectAllChildren(btn.previousElementSibling);
      restore('Press Ctrl+C', 3000);
    }
  });

  // ---------------------------------------------------------- <dialog>s ----
  document.addEventListener('click', function (e) {
    var el = e.target;
    if (!el || typeof el.closest !== 'function') return;
    var opener = el.closest('[data-dialog-open]');
    if (opener) {
      var dialog = document.getElementById(opener.getAttribute('data-dialog-open'));
      if (dialog && typeof dialog.showModal === 'function') dialog.showModal();
      return;
    }
    var closer = el.closest('[data-dialog-close]');
    if (closer) {
      var owner = closer.closest('dialog');
      if (owner) owner.close();
    }
  });

  // --------------------------------------------------- feedback launcher ----
  // Carry the originating page to the feedback form. The static
  // href="/feedback" stays the no-JS fallback; the /feedback handler sanitizes
  // ?from= (must start with "/") before round-tripping it.
  document.addEventListener('click', function (e) {
    var el = e.target;
    if (!el || typeof el.closest !== 'function') return;
    var link = el.closest('[data-feedback-link]');
    if (!link) return;
    link.href = '/feedback?from=' + encodeURIComponent(location.pathname + location.search);
  });

  // ------------------------------------------------ delayed redirect/reload --
  document.querySelectorAll('[data-redirect-to]').forEach(function (el) {
    var target = el.getAttribute('data-redirect-to');
    var delay = parseInt(el.getAttribute('data-redirect-after'), 10);
    if (!target || !(delay >= 0)) return;
    setTimeout(function () {
      location.href = target;
    }, delay);
  });
  document.querySelectorAll('[data-reload-after]').forEach(function (el) {
    var delay = parseInt(el.getAttribute('data-reload-after'), 10);
    if (!(delay >= 0)) return;
    setTimeout(function () {
      location.reload();
    }, delay);
  });

  // ------------------------------------------------- sensitive reveal --------
  // BUNYIP-371: secrets/codes (TOTP key + QR, recovery codes) render blurred by
  // default so a casual screen share does not expose them; the eye button flips
  // the `blur-sm` class. Best-effort: a web page cannot hide from native screen
  // capture the way a native app can, and the blur is defeated by disabling GPU
  // compositing - this stops accidental exposure, not a determined viewer.
  document.addEventListener('click', function (e) {
    var el = e.target;
    if (!el || typeof el.closest !== 'function') return;
    var btn = el.closest('[data-sensitive-toggle]');
    if (!btn) return;
    var wrap = btn.closest('[data-sensitive]');
    var value = wrap && wrap.querySelector('[data-sensitive-value]');
    if (!value) return;
    var blurred = value.classList.toggle('blur-sm');
    btn.setAttribute('aria-pressed', blurred ? 'false' : 'true');
    var label = btn.getAttribute('data-sensitive-label') || 'value';
    btn.setAttribute('aria-label', (blurred ? 'Reveal ' : 'Hide ') + label);
    var icon = btn.querySelector('i');
    if (icon) icon.className = blurred ? 'fa-regular fa-eye' : 'fa-regular fa-eye-slash';
  });
})();
