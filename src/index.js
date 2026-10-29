// GitHub sign-in broker for the portal's Deployments tab (POC, frontend GH-20).
//
// Stateless OAuth code exchange for the godronus-org-deploy-bot GitHub App:
// it holds only the App's client secret and gives the connecting user a GitHub
// user token. GitHub enforces what that token can reach, so the broker never
// has to trust its caller, and it never sees a Gcore credential.
//
//   GET  /login?origin=<portal origin>   popup: sets a state cookie, redirects to GitHub
//   GET  /callback?code&state             popup: exchanges the code, postMessages the token
//                                          to the origin from /login, closes
//   POST /refresh  { refresh_token }      CORS (allowed origins only): new token pair
//   GET  /asset?repo=o/r&id=<asset id>    CORS: streams a release asset using the caller's
//                                          own token (Authorization: Bearer …). GitHub's
//                                          asset storage sends no CORS headers, so the
//                                          portal cannot download it directly.
//
// Env: GITHUB_CLIENT_ID, ALLOWED_ORIGINS (comma-separated). Secret: GITHUB_CLIENT_SECRET.

import { getEnv } from 'fastedge::env';
import { getSecret } from 'fastedge::secret';

const STATE_COOKIE = 'gh_state';
const MESSAGE_TYPE = 'fastedge-github-auth';

const allowedOrigins = () =>
  (getEnv('ALLOWED_ORIGINS') ?? '').split(',').map((o) => o.trim()).filter(Boolean);

// FastEdge terminates TLS before the app, so request.url reports http://;
// GitHub must get the https callback that is registered on the App.
const callbackUrl = (url) => `https://${url.host}/callback`;

const noStore = { 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' };

const text = (status, body) =>
  new Response(body, { status, headers: { ...noStore, 'content-type': 'text/plain;charset=UTF-8' } });

function cookie(request, name) {
  for (const part of (request.headers.get('cookie') ?? '').split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return decodeURIComponent(v.join('='));
  }
  return null;
}

function nonce() {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

// Exchange a code or refresh token at GitHub. Returns GitHub's JSON as-is.
async function exchange(params) {
  const body = new URLSearchParams({
    client_id: getEnv('GITHUB_CLIENT_ID') ?? '',
    client_secret: getSecret('GITHUB_CLIENT_SECRET') ?? '',
    ...params,
  });
  const res = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: { accept: 'application/json', 'content-type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  return res.json();
}

function login(url) {
  const origin = url.searchParams.get('origin') ?? '';
  if (!allowedOrigins().includes(origin)) return text(403, 'origin not allowed');
  const state = nonce();
  const authorize = new URL('https://github.com/login/oauth/authorize');
  authorize.searchParams.set('client_id', getEnv('GITHUB_CLIENT_ID') ?? '');
  authorize.searchParams.set('redirect_uri', callbackUrl(url));
  authorize.searchParams.set('state', state);
  return new Response(null, {
    status: 302,
    headers: {
      ...noStore,
      location: authorize.toString(),
      // Popup flow: /login and /callback are both top-level on this origin, so Lax is enough.
      'set-cookie': `${STATE_COOKIE}=${encodeURIComponent(`${state} ${origin}`)}; Path=/callback; Max-Age=600; HttpOnly; Secure; SameSite=Lax`,
    },
  });
}

async function callback(request, url) {
  const [state, origin] = (cookie(request, STATE_COOKIE) ?? '').split(' ');
  if (!state || state !== url.searchParams.get('state') || !allowedOrigins().includes(origin)) {
    return text(400, 'invalid or expired sign-in — start again from the portal');
  }
  const code = url.searchParams.get('code');
  if (!code) return text(400, url.searchParams.get('error_description') ?? 'no code');

  const token = await exchange({ code, redirect_uri: callbackUrl(url) });
  if (!token.access_token) return text(502, `GitHub refused the sign-in: ${token.error ?? 'unknown error'}`);

  const message = JSON.stringify({
    type: MESSAGE_TYPE,
    access_token: token.access_token,
    expires_in: token.expires_in,
    refresh_token: token.refresh_token,
    refresh_token_expires_in: token.refresh_token_expires_in,
  });
  // The token goes only to the origin that started /login (allow-listed twice).
  const html = `<!doctype html><meta charset="utf-8"><title>GitHub sign-in</title>
<p>Signed in — you can close this window.</p>
<script>window.opener && window.opener.postMessage(${message}, ${JSON.stringify(origin)}); window.close();</script>`;
  return new Response(html, {
    status: 200,
    headers: {
      ...noStore,
      'content-type': 'text/html;charset=UTF-8',
      'content-security-policy': "default-src 'none'; script-src 'unsafe-inline'",
      'set-cookie': `${STATE_COOKIE}=; Path=/callback; Max-Age=0; HttpOnly; Secure; SameSite=Lax`,
    },
  });
}

// CORS for the allowed portal origins. Returns { cors } or { response } to send as-is.
function corsFor(request, methods, headers) {
  const origin = request.headers.get('origin') ?? '';
  if (!allowedOrigins().includes(origin)) return { response: text(403, 'origin not allowed') };
  const cors = { 'access-control-allow-origin': origin, vary: 'origin' };
  if (request.method !== 'OPTIONS') return { cors };
  return {
    response: new Response(null, {
      status: 204,
      headers: { ...cors, 'access-control-allow-methods': methods, 'access-control-allow-headers': headers, 'access-control-max-age': '600' },
    }),
  };
}

async function refresh(request) {
  const { cors, response } = corsFor(request, 'POST', 'content-type');
  if (response) return response;
  const { refresh_token: refreshToken } = await request.json().catch(() => ({}));
  if (!refreshToken) return text(400, 'refresh_token required');
  const token = await exchange({ grant_type: 'refresh_token', refresh_token: refreshToken });
  return new Response(JSON.stringify(token), {
    status: token.access_token ? 200 : 400,
    headers: { ...noStore, ...cors, 'content-type': 'application/json' },
  });
}

// GitHub naming: owner = alphanumerics and single hyphens; repo = [\w.-] but never
// "." or ".." (which would let the request path escape /repos/<owner>/<repo>).
const REPO = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/(?!\.{1,2}$)[\w.-]{1,100}$/;

// Hosts GitHub redirects asset downloads to (signed, short-lived URLs).
const ASSET_HOST = /^(objects|release-assets)\.githubusercontent\.com$/;

async function asset(request, url) {
  const { cors, response } = corsFor(request, 'GET', 'authorization');
  if (response) return response;
  const repo = url.searchParams.get('repo') ?? '';
  const id = url.searchParams.get('id') ?? '';
  const auth = request.headers.get('authorization') ?? '';
  if (!REPO.test(repo) || !/^\d+$/.test(id) || !auth.startsWith('Bearer ')) {
    return new Response('repo, numeric id and a Bearer token are required', { status: 400, headers: { ...noStore, ...cors } });
  }
  // The caller's own token: the broker adds no access of its own.
  const meta = await fetch(`https://api.github.com/repos/${repo}/releases/assets/${id}`, {
    headers: { accept: 'application/octet-stream', authorization: auth, 'user-agent': 'gdr-gh-broker', 'x-github-api-version': '2022-11-28' },
    redirect: 'manual',
  });
  let res = meta;
  if (meta.status >= 300 && meta.status < 400) {
    // The FastEdge JS runtime does not follow redirects; follow GitHub's one hop.
    const location = new URL(meta.headers.get('location') ?? '', 'https://github.com');
    if (location.protocol !== 'https:' || !ASSET_HOST.test(location.hostname)) {
      return new Response('unexpected asset redirect', { status: 502, headers: { ...noStore, ...cors } });
    }
    res = await fetch(location.toString(), { headers: { accept: 'application/octet-stream' } });
  }
  if (!res.ok) return new Response(`GitHub returned ${res.status}`, { status: res.status, headers: { ...noStore, ...cors } });
  return new Response(res.body, {
    status: 200,
    headers: { ...noStore, ...cors, 'content-type': 'application/octet-stream' },
  });
}

async function handle(request) {
  const url = new URL(request.url);
  if (url.pathname === '/login' && request.method === 'GET') return login(url);
  if (url.pathname === '/callback' && request.method === 'GET') return callback(request, url);
  if (url.pathname === '/refresh' && ['POST', 'OPTIONS'].includes(request.method)) return refresh(request);
  if (url.pathname === '/asset' && ['GET', 'OPTIONS'].includes(request.method)) return asset(request, url);
  return text(404, 'not found');
}

addEventListener('fetch', (event) => event.respondWith(handle(event.request)));
