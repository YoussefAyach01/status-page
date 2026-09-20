import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { checkUrlSyntax, isPublicIp, safeFetch, SsrfError } from '../src/ssrf.js';

describe('isPublicIp', () => {
  it.each([
    '127.0.0.1',
    '10.1.2.3',
    '172.16.0.1',
    '172.31.255.255',
    '192.168.1.1',
    '169.254.169.254',
    '100.64.0.1',
    '0.0.0.0',
    '224.0.0.1',
    '255.255.255.255',
    '::1',
    '::',
    'fe80::1',
    'fc00::1',
    'fd12:3456::1',
    '::ffff:127.0.0.1',
    '::ffff:7f00:1',
    '::ffff:169.254.169.254',
    '::ffff:a00:1',
    'ff02::1',
    '64:ff9b::7f00:1',
  ])('blocks %s', (ip) => {
    expect(isPublicIp(ip)).toBe(false);
  });
  it.each(['8.8.8.8', '1.1.1.1', '93.184.216.34', '172.32.0.1', '2606:4700:4700::1111'])(
    'allows %s',
    (ip) => {
      expect(isPublicIp(ip)).toBe(true);
    },
  );
  it('rejects non-IP strings', () => {
    expect(isPublicIp('example.com')).toBe(false);
  });
});

describe('checkUrlSyntax', () => {
  it.each([
    'file:///etc/passwd',
    'ftp://example.com/',
    'gopher://example.com/',
    'javascript:alert(1)',
    'not a url',
    'http://user:pw@example.com/',
    'http://127.0.0.1/',
    'http://localhost:8080/', // hostname passes syntax; blocked at DNS-lookup time (tested below)
    'http://2130706433/', // decimal form of 127.0.0.1
    'http://0x7f.0.0.1/',
    'http://127.1/',
    'http://[::1]/',
    'http://[::ffff:127.0.0.1]/',
    'http://169.254.169.254/latest/meta-data/',
    'https://example.com:22/',
    'https://example.com:6379/',
  ])('handles %s', (u) => {
    if (u === 'http://localhost:8080/') {
      expect(() => checkUrlSyntax(u)).not.toThrow();
    } else {
      expect(() => checkUrlSyntax(u)).toThrow(SsrfError);
    }
  });
  it('accepts normal public urls', () => {
    expect(checkUrlSyntax('https://example.com/hook?a=1').hostname).toBe('example.com');
    expect(() => checkUrlSyntax('http://example.com:8080/')).not.toThrow();
  });
});

describe('safeFetch against a local server', () => {
  let srv: http.Server;
  let base: string;
  let lastReq: http.IncomingMessage | undefined;
  beforeAll(async () => {
    srv = http.createServer((req, res) => {
      lastReq = req;
      if (req.url === '/redirect') {
        res.writeHead(302, { Location: 'http://169.254.169.254/' }).end();
      } else if (req.url === '/big') {
        res.writeHead(200);
        res.end('x'.repeat(200_000));
      } else if (req.url === '/hang') {
        // never respond
      } else {
        res.writeHead(200).end('hello');
      }
    });
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
    base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  });
  afterAll(() => {
    srv.closeAllConnections();
    srv.close();
  });

  it('refuses a loopback IP literal by default', async () => {
    await expect(safeFetch(`${base}/`)).rejects.toThrow(SsrfError);
    expect(lastReq).toBeUndefined();
  });
  it('refuses a hostname that resolves to a private address (localhost) and never connects', async () => {
    const port = new URL(base).port;
    await expect(
      safeFetch(`http://localhost:${port}/`, { allowedPorts: [Number(port)] }),
    ).rejects.toThrow(/non-public/);
    expect(lastReq).toBeUndefined();
  });
  it('blocks DNS rebinding style answers: ANY private address in the answer set rejects', async () => {
    const resolver = async () => [
      { address: '93.184.216.34', family: 4 },
      { address: '127.0.0.1', family: 4 },
    ];
    await expect(safeFetch('http://rebind.example/', { resolver })).rejects.toThrow(/non-public/);
  });
  it('blocks a hostname resolving to cloud metadata', async () => {
    const resolver = async () => [{ address: '169.254.169.254', family: 4 }];
    await expect(safeFetch('http://metadata.example/', { resolver })).rejects.toThrow(/non-public/);
  });
  it('connects to the validated address (public resolver answer is used, hostname never re-resolved)', async () => {
    // Resolver claims public IP 8.8.8.8; we can't reach it offline, so just prove the lookup result is what is dialled.
    const resolver = async () => [{ address: '127.0.0.1', family: 4 }];
    const port = Number(new URL(base).port);
    const r = await safeFetch(`http://any-name.test:${port}/`, { resolver, allowPrivate: true });
    expect(r.status).toBe(200);
    expect(r.bodySnippet).toBe('hello');
  });
  it('does not follow redirects (returns the 302)', async () => {
    const r = await safeFetch(`${base}/redirect`, { allowPrivate: true });
    expect(r.status).toBe(302);
  });
  it('caps the response snippet', async () => {
    const r = await safeFetch(`${base}/big`, { allowPrivate: true, maxBodyBytes: 100 });
    expect(r.status).toBe(200);
    expect(r.bodySnippet.length).toBeLessThanOrEqual(100);
  });
  it('times out on a hanging server', async () => {
    await expect(
      safeFetch(`${base}/hang`, { allowPrivate: true, timeoutMs: 300 }),
    ).rejects.toThrow();
  });
  it('strips forbidden headers such as Host', async () => {
    await safeFetch(`${base}/`, { allowPrivate: true, headers: { Host: 'evil.test', 'X-A': '1' } });
    expect(lastReq?.headers.host).toBe(new URL(base).host);
    expect(lastReq?.headers['x-a']).toBe('1');
  });
});
