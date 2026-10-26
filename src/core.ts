import { createHash } from "node:crypto";
import { getAbiItem, hexToBytes, hexToString, isAddress, keccak256, recoverTypedDataAddress, size, slice, toHex, type Address, type Hex, type PublicClient } from "viem";
import { contentAbi, inboxAbi, namesAbi, pushRelaysAbi, socialAbi } from "./abi.ts";
import { openSealed } from "./crypto.ts";
import { addressTarget, domain, KIND, types } from "./protocol.ts";

export const PUSH_INFO = "arobase:push";
export const MAX_DEVICES = 10;
export const MAX_SUB_LIFETIME_SEC = 120 * 86_400;
export const pushTypes = { Push: [{ name: "author", type: "address" }, { name: "bodyHash", type: "bytes32" }], Session: types.Session } as const;
export const MAX_TAG_KEYS = 200;
export const TAG_BUCKET = 4096n;
const TAG_KEY = /^0x[0-9a-f]{32}$/;
const DEVICE = /^0x[0-9a-f]{32}$/;
const B64URL = /^[A-Za-z0-9_-]+={0,2}$/;
export const PUSH_HOSTS = ["fcm.googleapis.com", "updates.push.services.mozilla.com", "push.apple.com", "notify.windows.com"];

export function isPushEndpoint(endpoint: string, extraHosts: string[] = []) {
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    return false;
  }
  if (url.protocol !== "https:" || url.username || url.password || (url.port && url.port !== "443")) return false;
  const host = url.hostname.toLowerCase();
  return [...PUSH_HOSTS, ...extraHosts.map((h) => h.trim().toLowerCase()).filter(Boolean)].some((h) => host === h || host.endsWith(`.${h}`));
}

export const NOTIFY_REASON: Record<number, string> = { 1: "mention", 2: "reply", 3: "note", 4: "repost", 5: "quote" };

export type PushSubscription = { endpoint: string; keys: { p256dh: string; auth: string } };

export type Sub = {
  a: Address;
  dev: Hex;
  sub: PushSubscription;
  exp: number;
  h?: number;
  l?: string;
  tk: Hex[];
};

export type SubRecord = Omit<Sub, "sub"> & { sub: PushSubscription | null };

export type Data = {
  network: string;
  registry: Address;
  registryRpcs: string[];
  contact: string;
  encSecret: Hex;
  oldEncSecrets: Hex[];
  vapidPublic: string;
  vapidPrivate: string;
  relayId?: number;
  pushContract?: Address;
  subs: Record<string, Sub>;
  cursors: Record<string, string>;
};

export type Config = {
  params: Record<string, unknown>;
  social: Address;
  chains: { chainId: number; role: number; content: Address; inbox: Address; rpcs: string[] }[];
  registryChainId: number;
};

export type Client = Pick<PublicClient, "getBlockNumber" | "getLogs" | "readContract">;
export type Clients = Map<number, Client>;
export type Proof = { c: number; tx: Hex; i: number };
export type Event = { to: Address; t: string; from?: Address; post?: Hex; x?: string; p?: Proof };

export function tagAt(tagKey: Hex, bucket: bigint): Hex {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(bucket);
  return `0x${createHash("sha256").update(Buffer.concat([Buffer.from(tagKey.slice(2), "hex"), b])).digest("hex")}`;
}

export function tagsForRange(keys: Hex[], from: bigint, to: bigint): Hex[] {
  const out: Hex[] = [];
  const first = from / TAG_BUCKET > 0n ? from / TAG_BUCKET - 1n : 0n;
  for (const k of keys) for (let b = first; b <= to / TAG_BUCKET; b++) out.push(tagAt(k, b));
  return out;
}

const proofOf = (chainId: number, l: { transactionHash: Hex | null; logIndex: number | null }): Proof | undefined =>
  l.transactionHash && l.logIndex !== null ? { c: chainId, tx: l.transactionHash, i: l.logIndex } : undefined;
export type Group = Event & { n: number };
export type Sender = (sub: PushSubscription, payload: string, urgency: "high" | "normal") => Promise<number>;

export const lc = (a: string) => a.toLowerCase();
export const short = (a: string) => `${a.slice(0, 6)}…${a.slice(-4)}`;
export const chunk = <T>(list: T[], n: number) => Array.from({ length: Math.ceil(list.length / n) }, (_, i) => list.slice(i * n, i * n + n));
export const pushParamOf = (cfg: Config) => cfg.params.push as { chainId: number; address: Address; deployBlock?: number } | undefined;

const subscribedEvent = getAbiItem({ abi: pushRelaysAbi, name: "Subscribed" });
const notifyEvent = getAbiItem({ abi: contentAbi, name: "Notify" });
const actedEvent = getAbiItem({ abi: socialAbi, name: "Acted" });
const encryptedEvent = getAbiItem({ abi: inboxAbi, name: "Encrypted" });
const messageEvent = getAbiItem({ abi: contentAbi, name: "Message" });

export function excerpt(payload: Hex) {
  try {
    const text = String(JSON.parse(hexToString(payload)).text ?? "").replace(/\s+/g, " ").trim();
    return text.length > 140 ? `${text.slice(0, 139)}…` : text || undefined;
  } catch {
    return undefined;
  }
}

export function openSubscription(secrets: Hex[], ciphertext: Hex): { b?: string; s?: Hex } | null {
  for (const s of secrets) {
    const raw = openSealed<{ b?: string; s?: Hex }>(hexToBytes(s), PUSH_INFO, ciphertext);
    if (raw) return raw;
  }
  return null;
}

export async function verifySub(
  raw: { b?: string; s?: Hex } | null,
  opts: { now?: number; allowHttp?: boolean; extraHosts?: string[] } = {},
): Promise<SubRecord | null> {
  const now = opts.now ?? Date.now() / 1000;
  if (!raw?.b || !raw.s) return null;
  let body: Partial<Sub> & { v?: number; sub?: PushSubscription | null };
  try {
    body = JSON.parse(raw.b);
  } catch {
    return null;
  }
  if (body.v !== 1 || typeof body.a !== "string" || !isAddress(body.a) || typeof body.dev !== "string" || !DEVICE.test(body.dev)) return null;
  const message = { author: body.a, bodyHash: keccak256(toHex(raw.b)) };
  const sig = raw.s;
  try {
    if (size(sig) === 65) {
      const signer = await recoverTypedDataAddress({ domain, types: pushTypes, primaryType: "Push", message, signature: sig });
      if (lc(signer) !== lc(body.a)) return null;
    } else if (size(sig) === 138) {
      const key = await recoverTypedDataAddress({ domain, types: pushTypes, primaryType: "Push", message, signature: slice(sig, 0, 65) });
      const expiry = BigInt(slice(sig, 130, 138));
      const delegator = await recoverTypedDataAddress({ domain, types: pushTypes, primaryType: "Session", message: { key, expiry }, signature: slice(sig, 65, 130) });
      if (lc(delegator) !== lc(body.a) || Number(expiry) < now) return null;
    } else return null;
  } catch {
    return null;
  }
  if (body.sub === null) return { a: body.a, dev: body.dev, sub: null, exp: 0, tk: [] };
  const s = body.sub;
  if (!s || typeof s.endpoint !== "string" || s.endpoint.length > 1024 || typeof s.keys?.p256dh !== "string" || typeof s.keys?.auth !== "string") return null;
  if (!B64URL.test(s.keys.p256dh) || s.keys.p256dh.length > 128 || !B64URL.test(s.keys.auth) || s.keys.auth.length > 64) return null;
  const exp = Number(body.exp);
  if (!Number.isSafeInteger(exp) || exp <= now) return null;
  const tk = (body as { tk?: unknown }).tk;
  if (tk !== undefined && (!Array.isArray(tk) || tk.length > MAX_TAG_KEYS || !tk.every((k) => typeof k === "string" && TAG_KEY.test(k)))) return null;
  if (!isPushEndpoint(s.endpoint, opts.extraHosts) && !(opts.allowHttp && /^https?:\/\//.test(s.endpoint))) return null;
  return {
    a: body.a,
    dev: body.dev,
    sub: { endpoint: s.endpoint, keys: { p256dh: s.keys.p256dh, auth: s.keys.auth } },
    exp: Math.min(exp, Math.floor(now + MAX_SUB_LIFETIME_SEC)),
    h: body.h ? 1 : 0,
    l: body.l === "en" ? "en" : "fr",
    tk: [...new Set((tk as Hex[] | undefined) ?? [])],
  };
}

export function applySubscription(subs: Record<string, Sub>, rec: SubRecord): "added" | "updated" | "removed" | "unknown" {
  const key = `${lc(rec.a)}:${rec.dev}`;
  if (!rec.sub) {
    if (!subs[key]) return "unknown";
    delete subs[key];
    return "removed";
  }
  const devices = Object.keys(subs).filter((k) => k.startsWith(`${lc(rec.a)}:`) && k !== key);
  if (devices.length >= MAX_DEVICES) delete subs[devices[0]];
  const isNew = !subs[key];
  subs[key] = rec as Sub;
  return isNew ? "added" : "updated";
}

export function pruneExpired(subs: Record<string, Sub>, now = Date.now() / 1000) {
  let removed = 0;
  for (const [k, s] of Object.entries(subs)) {
    if (!(s.exp >= now)) {
      delete subs[k];
      removed++;
    }
  }
  return removed;
}

export async function scanRange<T>(
  cursors: Record<string, string>,
  key: string,
  client: Pick<Client, "getBlockNumber">,
  fetcher: (from: bigint, to: bigint) => Promise<T[]>,
  maxSpan: bigint,
): Promise<T[]> {
  const latest = await client.getBlockNumber();
  const saved = cursors[key];
  if (!saved) {
    cursors[key] = String(latest + 1n);
    return [];
  }
  let from = BigInt(saved);
  const out: T[] = [];
  let span = maxSpan;
  while (from <= latest) {
    const to = from + span - 1n > latest ? latest : from + span - 1n;
    try {
      out.push(...(await fetcher(from, to)));
      from = to + 1n;
    } catch (err) {
      if (span <= 16n) throw err;
      span /= 4n;
    }
  }
  cursors[key] = String(latest + 1n);
  return out;
}

export async function syncSubscriptions(data: Data, cfg: Config, clients: Clients, opts: { maxSpan: bigint; allowHttp?: boolean; extraHosts?: string[]; now?: number }) {
  const p = pushParamOf(cfg)!;
  const client = clients.get(p.chainId)!;
  const relayId = BigInt(data.relayId!);
  const cursor = `subs:${p.address}:${data.relayId}`;
  const logs = await scanRange(data.cursors, cursor, client, (fromBlock, toBlock) =>
    client.getLogs({ address: p.address, event: subscribedEvent, args: { relayId }, fromBlock, toBlock, strict: true }),
    opts.maxSpan,
  );
  if (!data.cursors[`${cursor}:initial`]) {
    data.cursors[`${cursor}:initial`] = "1";
    const latest = BigInt(data.cursors[cursor]) - 1n;
    let from = BigInt(p.deployBlock ?? 0);
    while (from <= latest) {
      const to = from + opts.maxSpan - 1n > latest ? latest : from + opts.maxSpan - 1n;
      logs.push(...(await client.getLogs({ address: p.address, event: subscribedEvent, args: { relayId }, fromBlock: from, toBlock: to, strict: true })));
      from = to + 1n;
    }
  }
  const secrets = [data.encSecret, ...data.oldEncSecrets];
  const changes: { address: Address; change: ReturnType<typeof applySubscription> }[] = [];
  for (const l of logs) {
    const rec = await verifySub(openSubscription(secrets, l.args.ciphertext), { allowHttp: opts.allowHttp, extraHosts: opts.extraHosts, now: opts.now });
    if (rec) changes.push({ address: rec.a, change: applySubscription(data.subs, rec) });
  }
  pruneExpired(data.subs, opts.now);
  return changes;
}

export async function recentPosts(cfg: Config, clients: Clients, author: Address, cache: Map<string, { ids: Hex[]; at: number }>, now = Date.now()): Promise<Hex[]> {
  const cached = cache.get(lc(author));
  if (cached && now - cached.at < 5 * 60_000) return cached.ids;
  const lists = await Promise.all(
    cfg.chains
      .filter((c) => c.role !== 0)
      .map((c) =>
        clients
          .get(c.chainId)!
          .readContract({ address: c.content, abi: contentAbi, functionName: "page", args: [1, addressTarget(author), 2n ** 256n - 1n, 30n] })
          .then(([ids, metas]) => ids.filter((_, i) => metas[i].kind <= 1))
          .catch(() => [] as Hex[]),
      ),
  );
  const ids = [...new Set(lists.flat())].slice(0, 60);
  cache.set(lc(author), { ids, at: now });
  return ids;
}

export async function collect(
  data: Data,
  cfg: Config,
  clients: Clients,
  opts: { maxSpan: bigint; postsCache?: Map<string, { ids: Hex[]; at: number }>; onError?: (err: unknown) => void },
): Promise<Event[]> {
  const subs = Object.values(data.subs);
  const addrs = [...new Set(subs.map((s) => lc(s.a)))] as Address[];
  if (!addrs.length) return [];
  const events: Event[] = [];
  const social = clients.get(cfg.registryChainId)!;
  const scan = <T,>(key: string, client: Client, fetcher: (from: bigint, to: bigint) => Promise<T[]>) => scanRange(data.cursors, key, client, fetcher, opts.maxSpan);
  const tasks: Promise<unknown>[] = [];

  for (const { chainId: id, content: address } of cfg.chains.filter((c) => c.role === 1)) {
    const client = clients.get(id);
    if (!client) continue;
    tasks.push(
      scan(`notify:${id}:${address}`, client, async (fromBlock, toBlock) =>
        (await Promise.all(chunk(addrs, 50).map((to) => client.getLogs({ address, event: notifyEvent, args: { to }, fromBlock, toBlock, strict: true })))).flat(),
      ).then((logs) => {
        for (const l of logs) if (NOTIFY_REASON[l.args.reason]) events.push({ to: l.args.to, t: NOTIFY_REASON[l.args.reason], from: l.args.from, post: l.args.postId, p: proofOf(id, l) });
      }),
    );
  }

  const targets = new Map(addrs.map((a) => [addressTarget(a), a]));
  tasks.push(
    scan("follow", social, async (fromBlock, toBlock) =>
      (
        await Promise.all(
          chunk([...targets.keys()], 50).map((target) =>
            social.getLogs({ address: cfg.social, event: actedEvent, args: { kind: KIND.FOLLOW, target }, fromBlock, toBlock, strict: true }),
          ),
        )
      ).flat(),
    ).then((logs) => {
      for (const l of logs) {
        const to = targets.get(l.args.target);
        if (to && l.args.value === 1 && lc(l.args.author) !== to) events.push({ to, t: "follow", from: l.args.author, p: proofOf(cfg.registryChainId, l) });
      }
    }),
  );

  tasks.push(
    (async () => {
      const owners = new Map<Hex, Address>();
      const cache = opts.postsCache ?? new Map();
      for (const a of addrs) for (const id of await recentPosts(cfg, clients, a, cache)) owners.set(id, a);
      const logs = await scan("like", social, async (fromBlock, toBlock) =>
        owners.size
          ? (
              await Promise.all(
                chunk([...owners.keys()], 50).map((target) =>
                  social.getLogs({ address: cfg.social, event: actedEvent, args: { kind: KIND.REACT, target }, fromBlock, toBlock, strict: true }),
                ),
              )
            ).flat()
          : [],
      );
      for (const l of logs) {
        const to = owners.get(l.args.target);
        if (to && l.args.value === 1 && lc(l.args.author) !== to) events.push({ to, t: "like", from: l.args.author, post: l.args.target, p: proofOf(cfg.registryChainId, l) });
      }
    })(),
  );

  const platform = typeof cfg.params.platform === "string" && isAddress(cfg.params.platform) ? (cfg.params.platform as Address) : undefined;
  if (platform)
    for (const c of cfg.chains.filter((c) => c.role === 1)) {
      const client = clients.get(c.chainId);
      if (!client) continue;
      tasks.push(
        scan(`platform:${c.chainId}:${lc(platform)}`, client, (fromBlock, toBlock) =>
          client.getLogs({ address: c.content, event: messageEvent, args: { author: platform, kind: KIND.POST }, fromBlock, toBlock, strict: true }),
        ).then((logs) => {
          for (const l of logs) for (const to of addrs) if (to !== lc(platform)) events.push({ to, t: "announcement", from: platform, post: l.args.id, x: excerpt(l.args.payload), p: proofOf(c.chainId, l) });
        }),
      );
    }

  const byKey = new Map<Hex, Set<Address>>();
  for (const sub of subs) for (const k of sub.tk ?? []) byKey.set(k, (byKey.get(k) ?? new Set()).add(lc(sub.a) as Address));
  if (byKey.size)
    for (const c of cfg.chains.filter((c) => c.role !== 0 && c.inbox !== "0x0000000000000000000000000000000000000000")) {
      const client = clients.get(c.chainId);
      if (!client) continue;
      tasks.push(
        scan(`dm:${c.chainId}`, client, async (fromBlock, toBlock) => {
          const owners = new Map<Hex, Set<Address>>();
          for (const [k, users] of byKey) for (const tag of tagsForRange([k], fromBlock, toBlock)) owners.set(tag, users);
          const logs = (
            await Promise.all(chunk([...owners.keys()], 50).map((tag) => client.getLogs({ address: c.inbox, event: encryptedEvent, args: { tag }, fromBlock, toBlock, strict: true })))
          ).flat();
          return logs.flatMap((l) => [...(owners.get(l.args.tag) ?? [])].map((to) => ({ to, l })));
        }).then((hits) => {
          for (const { to, l } of hits) events.push({ to, t: "dm", p: proofOf(c.chainId, l) });
        }),
      );
    }

  const results = await Promise.allSettled(tasks);
  for (const r of results) if (r.status === "rejected") opts.onError?.(r.reason);
  return events;
}

export function groupEvents(events: Event[]): Group[] {
  const grouped = new Map<string, Group>();
  for (const e of events) {
    const key = `${lc(e.to)}|${e.t}|${e.post ?? ""}`;
    const g = grouped.get(key);
    if (g) g.n++;
    else grouped.set(key, { ...e, n: 1 });
  }
  return [...grouped.values()];
}

export const urgencyOf = (t: string): "high" | "normal" => (t === "dm" || t === "mention" ? "high" : "normal");

export const payloadFor = (g: Group, s: Sub, name?: string) =>
  JSON.stringify({ t: g.t, from: g.from, name, post: g.post, x: g.x, n: g.n, h: s.h, lang: s.l ?? "fr", p: g.p });

export async function handles(cfg: Config, clients: Clients, addrs: Address[]): Promise<Map<string, string>> {
  const names = cfg.params.names as Address | undefined;
  const out = new Map<string, string>();
  if (!names || !addrs.length) return out;
  const list = await clients
    .get(cfg.registryChainId)!
    .readContract({ address: names, abi: namesAbi, functionName: "namesOf", args: [addrs] })
    .catch(() => [] as readonly string[]);
  list.forEach((h, i) => h && out.set(lc(addrs[i]), h));
  return out;
}

export async function deliver(data: Data, groups: Group[], names: Map<string, string>, send: Sender) {
  const result = { sent: 0, expired: [] as Address[], failed: [] as { endpoint: string; status: number }[] };
  for (const g of groups) {
    for (const [key, s] of Object.entries(data.subs)) {
      if (lc(s.a) !== lc(g.to)) continue;
      const status = await send(s.sub, payloadFor(g, s, g.from ? names.get(lc(g.from)) : undefined), urgencyOf(g.t));
      if (status >= 200 && status < 300) result.sent++;
      else if (status === 404 || status === 410) {
        delete data.subs[key];
        result.expired.push(s.a);
      } else result.failed.push({ endpoint: s.sub.endpoint, status });
    }
  }
  return result;
}
