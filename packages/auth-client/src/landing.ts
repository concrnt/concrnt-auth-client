// §8.2 fragment の着地ページ。Authenticator が開いた 送り先 URL#id_token=… をこのページが受け、
// フラグメントの内容 (id_token / error / nonce) を exchange エンドポイントに JSON で POST して、開いたブラウザにセッションを発行させる。
// RP は GET 送り先 URL でこのページを返すだけでよく、フロントエンドに着地の実装は要らない。
// スクリプトは固定文字列なので CSP のハッシュで許可でき、exchange の URL と文言は <html> の data 属性で渡す

export const LANDING_SCRIPT = `(function () {
  var root = document.documentElement;
  var msg = document.getElementById('msg');
  var params = new URLSearchParams(location.hash.slice(1));
  var body = { id_token: params.get('id_token'), error: params.get('error'), nonce: params.get('nonce') };
  try { history.replaceState(null, '', location.pathname); } catch (e) {}
  var fail = function (text, callbackURL, code) {
    msg.textContent = text;
    if (callbackURL) {
      var url = new URL(callbackURL, location.origin);
      if (code) url.searchParams.set('error', code);
      var a = document.createElement('a');
      a.href = url.toString();
      a.textContent = root.getAttribute('data-back') || 'Back';
      msg.appendChild(document.createElement('br'));
      msg.appendChild(a);
    }
  };
  fetch(root.getAttribute('data-exchange'), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify(body)
  }).then(function (res) {
    return res.json().catch(function () { return {}; }).then(function (json) {
      var back = json.callbackURL || root.getAttribute('data-callback') || '/';
      if (!res.ok) return fail(json.message || res.statusText, back, json.code);
      if (json.status === 'denied') return fail(root.getAttribute('data-denied') || 'Denied', back, 'access_denied');
      location.replace(new URL(back, location.origin).toString());
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

export interface LandingPageOptions {
    /**
     * フラグメントの内容を `{ id_token, error, nonce }` の JSON で POST する先 (exchange エンドポイント。要求ごとに変わらない)。
     * 応答は `{ status: 'ok' | 'denied', callbackURL? }` か、失敗時は `{ code?, message?, callbackURL? }` を期待する
     */
    exchangeUrl: string
    /** 成功後に遷移する URL。exchange の応答に callbackURL があればそちらが優先される。既定 '/' */
    callbackURL?: string
    texts?: Partial<LandingTexts>
}

/** 着地ページの HTML */
export const renderLanding = ({ exchangeUrl, callbackURL, texts }: LandingPageOptions): string => {
    const t: LandingTexts = { ...DEFAULT_LANDING_TEXTS, ...texts }
    return `<!doctype html>
<html lang="en" data-exchange="${escapeHtml(exchangeUrl)}" data-callback="${escapeHtml(callbackURL ?? '/')}" data-denied="${escapeHtml(t.denied)}" data-back="${escapeHtml(t.back)}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>${escapeHtml(t.title)}</title>
<style>
  html, body { margin: 0; height: 100%; font-family: system-ui, sans-serif; background: #fff; color: #222; }
  main { min-height: 100%; display: flex; align-items: center; justify-content: center; padding: 24px; box-sizing: border-box; text-align: center; }
  a { color: inherit; }
</style>
</head>
<body>
<main><p id="msg">${escapeHtml(t.working)}</p></main>
<script>${LANDING_SCRIPT}</script>
</body>
</html>
`
}

/**
 * 着地ページの Response。GET 送り先 URL (= `${origin}${redirectPath}`) でそのまま返す。
 * キャッシュ禁止・Referrer 無し・スクリプトは自身のハッシュだけを許す CSP
 */
export const landingPage = async (options: LandingPageOptions): Promise<Response> =>
    new Response(renderLanding(options), {
        status: 200,
        headers: {
            'Content-Type': 'text/html; charset=utf-8',
            'Cache-Control': 'no-store',
            'Referrer-Policy': 'no-referrer',
            'Content-Security-Policy': `default-src 'none'; script-src ${await landingScriptHash()}; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'`
        }
    })

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
