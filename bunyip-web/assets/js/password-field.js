// The two behaviours every password input shares: the BUNYIP-282 show/hide
// toggle and the BUNYIP-575 submit guard. Rendered by `views::password`, loaded
// with `defer` by the pages that render those fields, and inert on a page that
// renders neither marker.
//
// Kept apart from `password.js` (live per-rule indicators + the HaveIBeenPwned
// lookup) so a form can take the toggle and the guard without also taking a
// submit button gated on an external service.
//
// Both halves are idempotent: they attach listeners only once per element, so a
// second render (e.g. a future htmx swap) does not double-bind.

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

// BUNYIP-575: a form carrying [data-pw-guard] checks its new-password pair in
// the browser and REFUSES to submit while a rule fails, showing the rule in the
// form's [data-pw-guard-msg] instead. A rejected password change answers with a
// redirect, and a redirect re-renders every password input empty, so refusing
// the round trip is the only thing that keeps the typed characters. The
// server-side `password_ok()` remains the backstop: with JS off the form posts
// exactly as it did before.
(function () {
  var forms = document.querySelectorAll('form[data-pw-guard]');
  forms.forEach(function (form) {
    if (form.dataset.pwGuardInit === '1') return;
    form.dataset.pwGuardInit = '1';
    var pw = form.querySelector('[data-pw-new]');
    var cf = form.querySelector('[data-pw-confirm]');
    var msg = form.querySelector('[data-pw-guard-msg]');
    if (!pw || !cf || !msg) return;

    // Mirrors `handlers::password_ok()` and the confirm check in the handlers.
    function firstProblem() {
      var v = pw.value;
      var ok = v.length >= 12 && /[a-z]/.test(v) && /[A-Z]/.test(v) &&
        /\d/.test(v) && /[^A-Za-z0-9]/.test(v);
      if (!ok) {
        return {
          field: pw,
          text: 'Password must be at least 12 characters and include upper and lowercase letters, a digit and a special character.'
        };
      }
      if (v !== cf.value) return { field: cf, text: "Passwords don't match." };
      return null;
    }
    function clear() {
      msg.textContent = '';
      msg.hidden = true;
    }

    form.addEventListener('submit', function (e) {
      var problem = firstProblem();
      if (!problem) { clear(); return; }
      e.preventDefault();
      msg.textContent = problem.text;
      msg.hidden = false;
      problem.field.focus();
    });
    pw.addEventListener('input', clear);
    cf.addEventListener('input', clear);
  });
})();
