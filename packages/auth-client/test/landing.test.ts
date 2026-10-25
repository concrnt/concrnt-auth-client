import { describe, expect, it } from 'vitest'
import { LANDING_SCRIPT, landingPage, landingScriptHash, renderLanding } from '../src/landing.js'

describe('landingPage', () => {
    it('returns no-store HTML whose CSP allows only the embedded script, with the exchange URL and texts in data attributes', async () => {
        const res = await landingPage({ exchangeUrl: '/api/login/exchange', callbackURL: '/home', texts: { working: '処理中…', denied: '拒否 <b>', back: '戻る' } })
        expect(res.status).toBe(200)
        expect(res.headers.get('content-type')).toContain('text/html')
        expect(res.headers.get('cache-control')).toBe('no-store')
        expect(res.headers.get('referrer-policy')).toBe('no-referrer')
        const csp = res.headers.get('content-security-policy')!
        expect(csp).toContain(`script-src ${await landingScriptHash()}`)
        expect(csp).toContain("default-src 'none'")
        expect(csp).toContain("connect-src 'self'")
        const html = await res.text()
        expect(html).toContain('data-exchange="/api/login/exchange"')
        expect(html).toContain('data-callback="/home"')
        expect(html).toContain('data-denied="拒否 &lt;b&gt;"')
        expect(html).toContain('data-back="戻る"')
        expect(html).toContain('<p id="msg">処理中…</p>')
        expect(html).toContain(`<script>${LANDING_SCRIPT}</script>`)
        // スクリプト自体は固定で、exchange の URL は data 属性から読む
        expect(LANDING_SCRIPT).toContain("getAttribute('data-exchange')")
        expect(LANDING_SCRIPT).not.toContain('/exchange')
        // 拒否応答 (error=access_denied&nonce=…) も nonce ごと exchange に転送する
        expect(LANDING_SCRIPT).toContain("params.get('nonce')")
    })

    it('the CSP hash matches the embedded script', async () => {
        const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(LANDING_SCRIPT))
        const expected = `'sha256-${btoa(String.fromCharCode(...new Uint8Array(digest)))}'`
        expect(await landingScriptHash()).toBe(expected)
        expect(renderLanding({ exchangeUrl: '/e' })).toContain('data-callback="/"')
    })
})
