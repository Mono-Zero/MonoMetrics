// monometrics.js
// Paste this as a <script> tag on any page you want counted.
// Sends: current page URL + whether the device looks mobile or desktop.
// Sends nothing else. No cookies, no localStorage, no fingerprinting.
//
// <script src="https://your-server.example/monometrics.js"
//         data-endpoint="https://your-server.example"></script>

(function () {
  var scriptTag = document.currentScript;
  var endpoint = (scriptTag && scriptTag.getAttribute('data-endpoint')) || '';

  if (!endpoint) {
    console.warn('MonoMetrics: no data-endpoint set on script tag, skipping.');
    return;
  }

  var isMobile = /Mobi|Android|iPhone|iPad|iPod/i.test(navigator.userAgent);

  fetch(endpoint.replace(/\/$/, '') + '/hit', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      url: location.pathname, // path only — no query string, no hash, no domain
      device: isMobile ? 'mobile' : 'desktop',
    }),
    keepalive: true,
  }).catch(function () {
    // Fail silently — a dead counter shouldn't break the page.
  });
})();
