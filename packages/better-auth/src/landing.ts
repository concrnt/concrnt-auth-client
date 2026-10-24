// §8.2 fragment の着地ページ。Authenticator が開いた redirect_uri#id_token=… をこのページが受け、
// フラグメントの内容を同じ要求の exchange に POST して、開いたブラウザにセッションを発行させる。
// スクリプトは固定文字列なので、CSP のハッシュで許可できる

export const LANDING_SCRIPT = `(function () {
  var msg = document.getElementById('msg');
  var path = location.pathname.replace(/\\/$/, '');
  var challenge = path.slice(path.lastIndexOf('/') + 1);
  var params = new URLSearchParams(location.hash.slice(1));
  var body = { id_token: params.get('id_token'), error: params.get('error') };
  try { history.replaceState(null, '', path); } catch (e) {}
  var base = path.slice(0, path.lastIndexOf('/callback/'));
  var fail = function (text, callbackURL, code) {
    msg.textContent = text;
    if (callbackURL) {
      var url = new URL(callbackURL, location.origin);
      if (code) url.searchParams.set('error', code);
      var a = document.createElement('a');
      a.href = url.toString();
      a.textContent = document.documentElement.getAttribute('data-back') || 'Back';
      msg.appendChild(document.createElement('br'));
      msg.appendChild(a);
    }
  };
  fetch(base + '/exchange/' + challenge, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify(body)
  }).then(function (res) {
    return res.json().catch(function () { return {}; }).then(function (json) {
      if (!res.ok) return fail(json.message || res.statusText, json.callbackURL, json.code);
      if (json.status === 'denied') return fail(document.documentElement.getAttribute('data-denied') || 'Denied', json.callbackURL, 'access_denied');
      location.replace(new URL(json.callbackURL || '/', location.origin).toString());
    });
  }).catch(function (e) { fail(String(e)); });
})();`

export interface LandingTexts {
    title: string
    working: string
    denied: string
    back: string
}

export const DEFAULT_LANDING_TEXTS: LandingTexts = {
    title: 'Sign-In with Concrnt',
    working: 'Signing in…',
    denied: 'Login was declined.',
    back: 'Back'
}

export const renderLanding = (texts: LandingTexts): string => `<!doctype html>
<html lang="en" data-denied="${escapeHtml(texts.denied)}" data-back="${escapeHtml(texts.back)}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>${escapeHtml(texts.title)}</title>
<style>
  html, body { margin: 0; height: 100%; font-family: system-ui, sans-serif; background: #fff; color: #222; }
  main { min-height: 100%; display: flex; align-items: center; justify-content: center; padding: 24px; box-sizing: border-box; text-align: center; }
  a { color: inherit; }
</style>
</head>
<body>
<main><p id="msg">${escapeHtml(texts.working)}</p></main>
<script>${LANDING_SCRIPT}</script>
</body>
</html>
`

let scriptHash: Promise<string> | undefined

/** `script-src` に書く `'sha256-…'`。固定文字列なので 1 回だけ計算する */
export const landingScriptHash = (): Promise<string> => {
    scriptHash ??= crypto.subtle.digest('SHA-256', new TextEncoder().encode(LANDING_SCRIPT)).then((digest) => {
        let binary = ''
        for (const byte of new Uint8Array(digest)) binary += String.fromCharCode(byte)
        return `'sha256-${btoa(binary)}'`
    })
    return scriptHash
}

const escapeHtml = (value: string): string =>
    value.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!)
