// BUNYIP-145: Server-Sent Events subscriber for the authenticated shells
// (dashboard + admin). Opens a long-lived EventSource against bunyip-api's
// /v1/events and reacts to five event names:
//
// - claims_changed: an admin granted / revoked something affecting this user
//   (membership, lifetime grant). Reload so the page picks up the new at+jwt
//   and dashboard tile state.
// - profile_changed: admin or self updated profile fields. Reload.
// - applications_changed: admin toggled an app slug or entitlement mapping.
// - resync: the broadcast lagged; reload rather than guess.
// - session_revoked: bunyip-api destroyed every active rt for this user
//   (admin deactivate, role change, BUNYIP-144). Redirect to /login.
//
// EventSource is opened with withCredentials so the access_token cookie rides
// along on the cross-subdomain GET (Lax + matching eTLD+1). Browser
// auto-reconnect handles transient drops.
//
// BUNYIP-380: bunyip-web is server-rendered, so every in-app navigation is a
// full page load. The pagehide listener closes the stream cleanly before the
// document unloads, so the browser stops logging "connection ... was
// interrupted while the page was loading" on each navigation. es.close() is
// idempotent, so closing an already-errored stream is harmless.
//
// BUNYIP-424: this used to be an inline <script> with the origin interpolated
// server-side. The origin now arrives as data-api-origin on this script's own
// tag, so no server value is ever emitted as executable JavaScript.
//
// BUNYIP-613: only the EventSource construction is wrapped. It is the one
// statement here that can throw (a malformed data-api-origin, a connection the
// browser refuses to open); the getAttribute and addEventListener calls around
// it cannot, so a bug in this file surfaces as a real error instead of being
// filed away as a hostile browser.
(function () {
  function report(level, what, e) {
    if (window.console && console[level]) console[level]('bunyip: ' + what, e || '');
  }

  var tag = document.currentScript || document.querySelector('script[data-api-origin]');
  var origin = tag && tag.getAttribute('data-api-origin');
  if (!origin || !window.EventSource) return;
  var es;
  try {
    es = new EventSource(origin + '/v1/events', { withCredentials: true });
  } catch (e) {
    // No live stream: claims changes and revocations are picked up on the next
    // navigation instead of immediately. That is a lost feature, not a nicety.
    report('error', 'live event stream could not be opened; this tab updates only on navigation', e);
    return;
  }
  window.addEventListener('pagehide', function () {
    try {
      es.close();
    } catch (e) {
      // The document is unloading, so the stream dies with it either way; a
      // failure here only brings back the browser's "interrupted" console noise.
      report('warn', 'live event stream could not be closed on pagehide', e);
    }
  });
  var reload = function () {
    window.location.reload();
  };
  es.addEventListener('claims_changed', reload);
  es.addEventListener('profile_changed', reload);
  es.addEventListener('applications_changed', reload);
  es.addEventListener('resync', reload);
  es.addEventListener('session_revoked', function () {
    window.location.href = '/login?toast_err=Session%20ended%20by%20an%20administrator.';
  });
})();
