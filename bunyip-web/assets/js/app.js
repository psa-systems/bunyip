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
  //
  // BUNYIP-549: the palette is the same semantic token pair each kind's
  // server-rendered counterpart uses - success the `success` badge
  // (views/ui.rs), error the offline banner (server_status.rs), info the
  // popover surface - so the pills track dark and high-contrast like every
  // other surface instead of sitting at a fixed stock-Tailwind colour.
  var TOAST_PALETTE = {
    success: 'bg-teal-500/15 text-teal-600 dark:text-teal-400 border border-teal-500/40',
    error: 'bg-destructive text-destructive-foreground',
    info: 'bg-popover text-popover-foreground border border-border',
  };

  window.bunyipToast = function (msg, kind) {
    var root = document.getElementById('bunyip-toast-root');
    if (!root) return;
    while (root.children.length >= 5) root.removeChild(root.firstChild);
    var palette = TOAST_PALETTE[kind || 'info'] || TOAST_PALETTE.info;
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

  // BUNYIP-613: a suppressed failure still has to be visible somewhere. Guarded
  // so a console-less environment does not throw inside the handler.
  var report = function (level, what, e) {
    if (window.console && console[level]) console[level]('bunyip: ' + what, e || '');
  };

  // Drain ?toast_ok= / ?toast_err= so a handler can surface a confirmation via
  // a 302 (`Location: /settings?toast_ok=Email%20updated`). The params are
  // stripped with history.replaceState so a reload does not re-fire the toast.
  //
  // BUNYIP-613: each try wraps only the statement that can throw (the URL parse,
  // the replaceState), so a bug in the toast call itself is not swallowed as a
  // browser quirk.
  var url = null;
  try {
    url = new URL(window.location.href);
  } catch (e) {
    // Nothing to drain without a parsed URL: the toast the redirect carried is
    // lost and the params stay in the address bar.
    report('warn', 'location could not be parsed; a redirect toast may be lost', e);
  }
  if (url) {
    var ok = url.searchParams.get('toast_ok');
    var err = url.searchParams.get('toast_err');
    if (ok || err) {
      url.searchParams.delete('toast_ok');
      url.searchParams.delete('toast_err');
      try {
        history.replaceState(null, '', url.pathname + (url.search || '') + url.hash);
      } catch (e) {
        // Still show the toast: the params survive, so a reload repeats it, and
        // a duplicate confirmation beats a missing one.
        report('warn', 'toast parameters could not be stripped; a reload will repeat the toast', e);
      }
      if (ok) window.bunyipToast(ok, 'success');
      if (err) window.bunyipToast(err, 'error');
    }
  }

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

  // ------------------------------------------------------ feedback form -----
  // Progressive enhancement for /feedback. BUNYIP-540: an in-flight submit
  // state (disable + spinner) and client-side attachment validation with image
  // previews. BUNYIP-541: inline per-field validation (email + required
  // message) that catches the common invalid case before a round-trip, marks
  // the field aria-invalid, renders the message in that field's own slot, and
  // moves focus to the first invalid field - no reload, no data loss. The no-JS
  // path stays fully functional: the native file input keeps its id so the
  // styled label still opens the picker, and the server re-validates every
  // field and file authoritatively. The limits and the email rule mirror the
  // Rust in skin::content / handlers::validate so client and server agree.
  (function () {
    var form = document.querySelector('[data-feedback-form]');
    if (!form) return;
    var MAX_FILES = 3;
    var MAX_BYTES = 5 * 1024 * 1024;
    var ALLOWED = ['image/png', 'image/jpeg', 'image/webp', 'image/gif', 'text/plain'];
    var input = form.querySelector('[data-feedback-input]');
    var fileLabel = form.querySelector('[data-feedback-filelabel]');
    var previews = form.querySelector('[data-feedback-previews]');
    var fileError = form.querySelector('[data-feedback-fileerror]');
    var submitBtn = form.querySelector('[data-feedback-submit]');
    var spinner = form.querySelector('[data-feedback-spinner]');
    var submitLabel = form.querySelector('[data-feedback-submit-label]');
    var emailInput = form.querySelector('#email');
    var messageInput = form.querySelector('#message');
    var objectUrls = [];

    function fmtSize(n) {
      if (n >= 1024 * 1024) return (n / (1024 * 1024)).toFixed(1) + ' MB';
      if (n >= 1024) return Math.round(n / 1024) + ' KB';
      return n + ' B';
    }
    function clearPreviews() {
      objectUrls.forEach(function (u) {
        URL.revokeObjectURL(u);
      });
      objectUrls = [];
      if (previews) {
        previews.textContent = '';
        previews.classList.add('hidden');
      }
    }
    function setFileError(msg) {
      if (!fileError) return;
      if (msg) {
        fileError.textContent = msg;
        fileError.classList.remove('hidden');
      } else {
        fileError.textContent = '';
        fileError.classList.add('hidden');
      }
    }
    // BUNYIP-541 inline field validation. Each function returns '' when valid,
    // else the exact message the server would return, so client and server
    // agree and an inline error reads the same whichever side caught it.
    // Mirrors bunyip-web/src/handlers/validate.rs::email.
    function validateEmail(v) {
      var t = v.trim();
      if (t === '') return ''; // optional, for follow-up
      if (t.length > 254) return 'Email must be 254 characters or fewer';
      var at = t.indexOf('@');
      if (at === -1) return 'Email must contain an @';
      var local = t.slice(0, at);
      var domain = t.slice(at + 1); // everything after the first @, as split_once does
      if (local === '' || domain === '') return 'Email must have characters on both sides of @';
      if (domain.indexOf('.') === -1) return 'Email domain must contain a dot';
      if (/\s/.test(t)) return 'Email must not contain whitespace';
      return '';
    }
    function validateMessage(v) {
      return v.trim() === '' ? 'Please enter a message.' : '';
    }
    // Set or clear an inline error under a field: flip aria-invalid on the
    // input (the aria-[invalid=true]: variant paints the red border) and fill
    // the field's own [data-feedback-error] slot.
    function setFieldError(el, msg) {
      if (!el) return;
      var slot = form.querySelector('[data-feedback-error="' + el.id + '"]');
      if (msg) {
        el.setAttribute('aria-invalid', 'true');
        if (slot) {
          slot.textContent = msg;
          slot.classList.remove('hidden');
        }
      } else {
        el.setAttribute('aria-invalid', 'false');
        if (slot) {
          slot.textContent = '';
          slot.classList.add('hidden');
        }
      }
    }
    // (input element, validator) pairs, in DOM order so "first invalid" is the
    // topmost one for focus.
    var FIELD_CHECKS = [
      { el: emailInput, fn: validateEmail },
      { el: messageInput, fn: validateMessage },
    ];

    // Returns '' when the selection is within the limits, else the message.
    function validate(files) {
      if (files.length > MAX_FILES) return 'Up to ' + MAX_FILES + ' files only.';
      for (var i = 0; i < files.length; i++) {
        var f = files[i];
        if (ALLOWED.indexOf(f.type) === -1) {
          return 'Only PNG, JPEG, WebP, GIF, and plain text files are allowed.';
        }
        if (f.size > MAX_BYTES) return '"' + f.name + '" is larger than 5 MB.';
      }
      return '';
    }
    function render() {
      clearPreviews();
      var files = input && input.files ? input.files : [];
      if (!files.length) {
        if (fileLabel) fileLabel.textContent = 'No file chosen';
        setFileError('');
        return;
      }
      if (fileLabel) {
        fileLabel.textContent =
          files.length === 1 ? '1 file selected' : files.length + ' files selected';
      }
      setFileError(validate(files));
      if (previews) previews.classList.remove('hidden');
      for (var i = 0; i < files.length; i++) {
        var f = files[i];
        var chip = document.createElement('div');
        chip.className =
          'flex min-w-0 items-center gap-2 rounded-md border border-border bg-muted/40 p-2 text-sm';
        if (f.type.indexOf('image/') === 0) {
          var url = URL.createObjectURL(f);
          objectUrls.push(url);
          var img = document.createElement('img');
          img.src = url;
          img.alt = '';
          img.className = 'h-10 w-10 shrink-0 rounded object-cover';
          chip.appendChild(img);
        } else {
          var box = document.createElement('span');
          box.className =
            'inline-flex h-10 w-10 shrink-0 items-center justify-center rounded bg-muted text-xs font-medium text-muted-foreground';
          box.textContent = 'TXT';
          chip.appendChild(box);
        }
        var meta = document.createElement('div');
        meta.className = 'min-w-0';
        var nm = document.createElement('div');
        nm.className = 'truncate font-medium';
        nm.textContent = f.name;
        var sz = document.createElement('div');
        sz.className = 'text-xs text-muted-foreground';
        sz.textContent = fmtSize(f.size);
        meta.appendChild(nm);
        meta.appendChild(sz);
        chip.appendChild(meta);
        if (previews) previews.appendChild(chip);
      }
    }
    if (input) input.addEventListener('change', render);

    // Validate a field on blur, and once it is showing an error, re-validate on
    // every keystroke so the message clears the moment the input becomes valid.
    FIELD_CHECKS.forEach(function (c) {
      if (!c.el) return;
      c.el.addEventListener('blur', function () {
        setFieldError(c.el, c.fn(c.el.value));
      });
      c.el.addEventListener('input', function () {
        if (c.el.getAttribute('aria-invalid') === 'true') {
          setFieldError(c.el, c.fn(c.el.value));
        }
      });
    });

    form.addEventListener('submit', function (e) {
      // BUNYIP-541: validate every field first, mark each invalid one inline,
      // and remember the topmost so focus lands there. This catches the common
      // invalid case (bad email, empty message) in the browser with no
      // round-trip and no data loss; the server still validates as a backstop.
      var firstInvalid = null;
      FIELD_CHECKS.forEach(function (c) {
        if (!c.el) return;
        var msg = c.fn(c.el.value);
        setFieldError(c.el, msg);
        if (msg && !firstInvalid) firstInvalid = c.el;
      });
      // Block a submit the client already knows the server will reject for an
      // attachment, and point the user at the file control if nothing earlier
      // is invalid.
      if (input && input.files && input.files.length) {
        var ferr = validate(input.files);
        setFileError(ferr);
        if (ferr && !firstInvalid) firstInvalid = input;
      }
      if (firstInvalid) {
        e.preventDefault();
        if (typeof firstInvalid.focus === 'function') firstInvalid.focus();
        return;
      }
      // Guard a double submit, then show the in-flight state. The full-page
      // navigation keeps it visible until the response renders.
      if (form.dataset.feedbackSubmitting === '1') {
        e.preventDefault();
        return;
      }
      form.dataset.feedbackSubmitting = '1';
      if (submitBtn) submitBtn.disabled = true;
      if (spinner) spinner.classList.remove('hidden');
      if (submitLabel) submitLabel.textContent = 'Sending...';
    });
  })();
})();
