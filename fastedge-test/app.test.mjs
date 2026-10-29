import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { defineTestSuite, runAndExit, runHttpRequest, assertHttpStatus } from '@gcoredev/fastedge-test/test';

const here = dirname(fileURLToPath(import.meta.url));
const PORTAL = 'https://portal.example.com';

function assert(condition, message) {
  if (!condition) throw new Error(message);
}
const header = (res, name) => res.headers[name] ?? res.headers[name.toLowerCase()];

await runAndExit(defineTestSuite({
  wasmPath: resolve(here, '../wasm/gh-broker.wasm'),
  // fastedge-test 0.2.6: dotenv via runnerConfig.dotenv, not applyDotenv (FUTURE F-10).
  runnerConfig: { dotenv: { enabled: true, path: resolve(here, 'env/default') } },
  tests: [
    {
      name: '/login from an allowed origin redirects to GitHub with state + cookie',
      async run(runner) {
        const res = await runHttpRequest(runner, { path: `/login?origin=${encodeURIComponent(PORTAL)}`, method: 'GET' });
        assertHttpStatus(res, 302);
        const location = new URL(header(res, 'location'));
        assert(location.origin === 'https://github.com' && location.pathname === '/login/oauth/authorize', `location ${location}`);
        assert(location.searchParams.get('client_id') === 'Iv1.testclient', 'client_id');
        assert(location.searchParams.get('redirect_uri')?.endsWith('/callback'), 'redirect_uri');
        const state = location.searchParams.get('state');
        assert(/^[0-9a-f]{48}$/.test(state), 'state is a 24-byte hex nonce');
        const cookie = [header(res, 'set-cookie')].flat().join('\n'); // runner returns set-cookie as an array
        assert(cookie.includes(`gh_state=${encodeURIComponent(`${state} ${PORTAL}`)}`), `cookie ${cookie}`);
        assert(/HttpOnly/.test(cookie) && /Secure/.test(cookie) && /Path=\/callback/.test(cookie), 'cookie flags');
      },
    },
    {
      name: '/login from any other origin is refused',
      async run(runner) {
        const res = await runHttpRequest(runner, { path: '/login?origin=https://evil.example.com', method: 'GET' });
        assertHttpStatus(res, 403);
      },
    },
    {
      name: '/callback without a matching state cookie is refused (no GitHub call)',
      async run(runner) {
        const res = await runHttpRequest(runner, { path: '/callback?code=x&state=abc', method: 'GET' });
        assertHttpStatus(res, 400);
      },
    },
    {
      name: '/refresh from a foreign origin is refused',
      async run(runner) {
        const res = await runHttpRequest(runner, {
          path: '/refresh', method: 'POST',
          headers: { origin: 'https://evil.example.com', 'content-type': 'application/json' },
          body: '{"refresh_token":"x"}',
        });
        assertHttpStatus(res, 403);
      },
    },
    {
      name: '/refresh preflight from the portal gets CORS for that origin only',
      async run(runner) {
        const res = await runHttpRequest(runner, { path: '/refresh', method: 'OPTIONS', headers: { origin: PORTAL } });
        assertHttpStatus(res, 204);
        assert(header(res, 'access-control-allow-origin') === PORTAL, 'allow-origin');
      },
    },
    {
      name: 'anything else is 404',
      async run(runner) {
        assertHttpStatus(await runHttpRequest(runner, { path: '/', method: 'GET' }), 404);
      },
    },
  ],
}));
