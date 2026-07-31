// Keyboard affordances for the admin users list (BUNYIP-410): arrow-key
// navigation inside a [data-segmented] radiogroup and Space-key activation of a
// [data-sort-header] column header.
//
// BUNYIP-424: extracted from the USERS_FILTER_JS inline <script> constant in
// handlers::admin so script-src can be 'self' with no 'unsafe-inline'.
(function () {
  document.addEventListener('keydown', function (e) {
    var el = e.target;
    if (!el || !el.closest) return;
    var group = el.closest('[data-segmented]');
    if (group && el.getAttribute('role') === 'radio') {
      var radios = Array.prototype.slice.call(group.querySelectorAll('[role=radio]'));
      var i = radios.indexOf(el);
      var n = null;
      if (e.key === 'ArrowRight' || e.key === 'ArrowDown') n = radios[(i + 1) % radios.length];
      else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') n = radios[(i - 1 + radios.length) % radios.length];
      if (n) {
        e.preventDefault();
        n.focus();
        n.click();
      }
      return;
    }
    if (e.key === ' ' && el.matches && el.matches('[data-sort-header]')) {
      e.preventDefault();
      el.click();
    }
  });
})();
