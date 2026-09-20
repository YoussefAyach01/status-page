/**
 * SSRF-safe outbound HTTP. Users give us URLs and we fetch them from inside our network, so a
 * naive fetch() would let them reach localhost, cloud metadata (169.254.169.254), or internal
 * services. Defences, in order:
 *   1. only http/https, no embedded credentials, restricted ports
 *   2. IP-literal hosts are checked directly (WHATWG URL already normalises 0x7f.1, 2130706433...)
 *   3. hostnames are resolved by OUR lookup function, which rejects the connection if ANY resolved
 *      address is non-public. The socket connects to the exact address we validated, so DNS
 *      rebinding (resolve public, then connect private) is impossible: there is no second lookup.
 *   4. redirects are never followed (a public URL could 302 to an internal one)
 *   5. hard timeout and response-size cap
 */
import { BlockList, isIP } from 'node:net';
import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';

export class SsrfError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SsrfError';
  }
}

const blocked = new BlockList();
const v4: [string, number][] = [
  ['0.0.0.0', 8], // "this" network
  ['10.0.0.0', 8],
  ['100.64.0.0', 10], // carrier-grade NAT
  ['127.0.0.0', 8],
  ['169.254.0.0', 16], // link-local incl. cloud metadata
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.88.99.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4], // reserved + broadcast
];
for (const [a, p] of v4) blocked.addSubnet(a, p, 'ipv4');
const v6: [string, number][] = [
  ['::', 128],
  ['::1', 128],
  ['64:ff9b::', 96], // NAT64
  ['100::', 64],
  ['2001:db8::', 32],
  ['2002::', 16], // 6to4
  ['fc00::', 7], // unique local
  ['fe80::', 10], // link-local
  ['fec0::', 10],
  ['ff00::', 8], // multicast
];
for (const [a, p] of v6) blocked.addSubnet(a, p, 'ipv6');

/** True if the address is safe to connect to from a server (public unicast). */
export function isPublicIp(ip: string): boolean {
  const fam = isIP(ip);
  if (fam === 0) return false;
  if (fam === 6) {
    // IPv4-mapped (::ffff:a.b.c.d or ::ffff:7f00:1): judge by the embedded IPv4 address.
    // (Node's BlockList treats IPv4 as mapped IPv6, so a blanket ::ffff:0:0/96 rule would block
    // every IPv4 address.) Normalise via URL so both notations look the same.
    const host = new URL(`http://[${ip}]/`).hostname.replace(/^\[|\]$/g, '');
    const m = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(host);
    if (m) {
      const hi = parseInt(m[1]!, 16);
      const lo = parseInt(m[2]!, 16);
      return isPublicIp(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`);
    }
    if (host.toLowerCase().startsWith('::ffff:')) return false; // unparseable mapped form: refuse
  }
  return !blocked.check(ip, fam === 4 ? 'ipv4' : 'ipv6');
}

export interface TargetPolicy {
  /** Local dev/tests only. Disables the private-network check. */
  allowPrivate?: boolean;
  allowedPorts?: number[];
}
const DEFAULT_PORTS = [80, 443, 8080, 8443];

/** Synchronous, no-network validation of the URL itself. Returns the parsed URL. */
export function checkUrlSyntax(raw: string, policy: TargetPolicy = {}): URL {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new SsrfError('Invalid URL');
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:')
    throw new SsrfError('Only http and https URLs are allowed');
  if (u.username || u.password)
    throw new SsrfError('URLs with embedded credentials are not allowed');
  if (raw.length > 2048) throw new SsrfError('URL too long');
  const port = u.port ? Number(u.port) : u.protocol === 'https:' ? 443 : 80;
  const ports = policy.allowedPorts ?? DEFAULT_PORTS;
  if (!policy.allowPrivate && !ports.includes(port)) {
    throw new SsrfError(`Port ${port} is not allowed (allowed: ${ports.join(', ')})`);
  }
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (isIP(host) && !policy.allowPrivate && !isPublicIp(host)) {
    throw new SsrfError('Target address is not a public IP');
  }
  return u;
}

type LookupCb = (
  err: NodeJS.ErrnoException | null,
  address: string | dns.LookupAddress[],
  family?: number,
) => void;
type Resolver = (host: string) => Promise<{ address: string; family: number }[]>;

const systemResolver: Resolver = (host) => dns.promises.lookup(host, { all: true, verbatim: true });

/** Builds the `lookup` option: resolves, validates ALL answers, hands back only validated addresses. */
export function makeSafeLookup(policy: TargetPolicy = {}, resolve: Resolver = systemResolver) {
  return (hostname: string, options: dns.LookupOptions, cb: LookupCb) => {
    resolve(hostname).then(
      (addrs) => {
        if (addrs.length === 0) return cb(new SsrfError('Host did not resolve'), '', 0);
        if (!policy.allowPrivate && addrs.some((a) => !isPublicIp(a.address))) {
          return cb(new SsrfError('Host resolves to a non-public address'), '', 0);
        }
        if (options.all) return cb(null, addrs);
        const first = addrs[0]!;
        cb(null, first.address, first.family);
      },
      (e: NodeJS.ErrnoException) => cb(e, '', 0),
    );
  };
}

export interface SafeFetchOptions extends TargetPolicy {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  maxBodyBytes?: number;
  resolver?: Resolver; // test hook
}
export interface SafeFetchResult {
  status: number;
  bodySnippet: string;
  durationMs: number;
}

const FORBIDDEN_HEADERS = new Set([
  'host',
  'content-length',
  'connection',
  'transfer-encoding',
  'upgrade',
  'proxy-authorization',
  'te',
  'trailer',
]);

export async function safeFetch(
  rawUrl: string,
  opts: SafeFetchOptions = {},
): Promise<SafeFetchResult> {
  const url = checkUrlSyntax(rawUrl, opts);
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const maxBody = opts.maxBodyBytes ?? 8 * 1024;
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(opts.headers ?? {})) {
    if (!FORBIDDEN_HEADERS.has(k.toLowerCase())) headers[k] = v;
  }
  const started = Date.now();
  const lib = url.protocol === 'https:' ? https : http;

  return new Promise<SafeFetchResult>((resolve, reject) => {
    const req = lib.request(
      url,
      {
        method: opts.method ?? 'GET',
        headers: {
          'User-Agent': 'cron-hooks/0.1',
          ...headers,
          ...(opts.body !== undefined
            ? { 'Content-Length': String(Buffer.byteLength(opts.body)) }
            : {}),
        },
        lookup: makeSafeLookup(opts, opts.resolver) as never,
        agent: false, // no connection reuse: every request must go through our lookup
      },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        res.on('data', (c: Buffer) => {
          if (size < maxBody) chunks.push(c.subarray(0, maxBody - size));
          size += c.length;
          if (size > maxBody * 8) res.destroy(); // stop downloading a huge body; status is already known
        });
        const finish = () =>
          resolve({
            status: res.statusCode ?? 0,
            bodySnippet: Buffer.concat(chunks).toString('utf8').slice(0, 1000),
            durationMs: Date.now() - started,
          });
        res.on('end', finish);
        res.on('close', finish);
        res.on('error', finish);
      },
    );
    // Total deadline, not just idle timeout: a slow-drip server can't hold us forever.
    const timer = setTimeout(
      () => req.destroy(new Error(`Timed out after ${timeoutMs}ms`)),
      timeoutMs,
    );
    req.on('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
    req.on('close', () => clearTimeout(timer));
    if (opts.body !== undefined) req.write(opts.body);
    req.end();
  });
}
