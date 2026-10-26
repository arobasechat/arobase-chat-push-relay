import { x25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, concat, keccak256, toHex, type Address, type Hex, type LocalAccount } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import type { Client, Config, Data, Sub } from "../src/core.ts";
import { PUSH_INFO, pushTypes } from "../src/core.ts";
import { sealTo } from "../src/crypto.ts";
import { domain, signSession } from "../src/protocol.ts";

export const NOW = 1_800_000_000;

export const account = () => privateKeyToAccount(generatePrivateKey());

export const pushSub = (id = "a") => ({
  endpoint: `https://fcm.googleapis.com/fcm/send/${id}`,
  keys: { p256dh: `p256dh-${id}`, auth: `auth-${id}` },
});

export type Record_ = { dev?: Hex; sub?: ReturnType<typeof pushSub> | null; exp?: number; h?: number; l?: string; tk?: unknown };

export async function signedRecord(
  identity: LocalAccount,
  record: Record_,
  opts: { session?: { key: LocalAccount; expiry: bigint }; author?: Address } = {},
) {
  const author = opts.author ?? identity.address;
  const b = JSON.stringify({ v: 1, a: author, dev: "0x00000000000000000000000000000001", sub: pushSub(), exp: NOW + 30 * 86_400, ...record });
  const message = { author, bodyHash: keccak256(toHex(b)) };
  if (!opts.session) {
    const s = await identity.signTypedData({ domain, types: pushTypes, primaryType: "Push", message });
    return { b, s };
  }
  const raw = await opts.session.key.signTypedData({ domain, types: pushTypes, primaryType: "Push", message });
  return { b, s: concat([raw, await signSession(identity, opts.session.key.address, opts.session.expiry)]) };
}

export function relayKeys() {
  const secret = x25519.utils.randomSecretKey();
  return { secret: bytesToHex(secret), pub: x25519.getPublicKey(secret) };
}

export const seal = (pub: Uint8Array, raw: { b: string; s: Hex }) => sealTo(pub, PUSH_INFO, raw);

export function emptyData(over: Partial<Data> = {}): Data {
  return {
    network: "test",
    registry: "0x0000000000000000000000000000000000000001",
    registryRpcs: [],
    contact: "mailto:test@example.org",
    encSecret: relayKeys().secret,
    oldEncSecrets: [],
    vapidPublic: "",
    vapidPrivate: "",
    relayId: 0,
    pushContract: "0x00000000000000000000000000000000000000a1",
    subs: {},
    cursors: {},
    ...over,
  };
}

export function sub(a: Address, over: Partial<Sub> = {}): Sub {
  return { a, dev: "0x00000000000000000000000000000001", sub: pushSub(a.slice(2, 8)), exp: NOW + 86_400, h: 0, l: "fr", tk: [], ...over };
}

export type FakeLog = { event: string; args: Record<string, unknown>; blockNumber: bigint; address?: Address; transactionHash?: Hex; logIndex?: number };

const matches = (expected: unknown, actual: unknown) => {
  const norm = (v: unknown) => (typeof v === "string" ? v.toLowerCase() : v);
  if (Array.isArray(expected)) return expected.some((e) => norm(e) === norm(actual));
  return norm(expected) === norm(actual);
};

export function fakeClient(opts: { latest?: bigint; logs?: FakeLog[]; read?: Record<string, (args: readonly unknown[]) => unknown>; failRanges?: (from: bigint, to: bigint) => boolean }) {
  const calls: { event: string; from: bigint; to: bigint }[] = [];
  const client = {
    latest: opts.latest ?? 100n,
    calls,
    getBlockNumber: async () => client.latest,
    getLogs: async (p: { address?: Address; event: { name: string }; args?: Record<string, unknown>; fromBlock: bigint; toBlock: bigint }) => {
      calls.push({ event: p.event.name, from: p.fromBlock, to: p.toBlock });
      if (opts.failRanges?.(p.fromBlock, p.toBlock)) throw new Error("range too large");
      return (opts.logs ?? []).map((l, i) => ({ transactionHash: id(Number(l.blockNumber) * 1000 + i), logIndex: i, ...l })).filter(
        (l) =>
          l.event === p.event.name &&
          l.blockNumber >= p.fromBlock &&
          l.blockNumber <= p.toBlock &&
          (!l.address || !p.address || l.address.toLowerCase() === p.address.toLowerCase()) &&
          Object.entries(p.args ?? {}).every(([k, v]) => matches(v, l.args[k])),
      );
    },
    readContract: async (p: { functionName: string; args?: readonly unknown[] }) => {
      const fn = opts.read?.[p.functionName];
      if (!fn) throw new Error(`readContract ${p.functionName} non simulé`);
      return fn(p.args ?? []);
    },
  };
  return client as typeof client & Client;
}

export const config = (over: Partial<Config> = {}): Config => ({
  params: {},
  social: "0x00000000000000000000000000000000000000c1",
  registryChainId: 100,
  chains: [
    { chainId: 100, role: 0, content: "0x0000000000000000000000000000000000000000", inbox: "0x0000000000000000000000000000000000000000", rpcs: [] },
    { chainId: 5042, role: 1, content: "0x00000000000000000000000000000000000000c2", inbox: "0x00000000000000000000000000000000000000c3", rpcs: [] },
  ],
  ...over,
});

export const id = (n: number) => `0x${n.toString(16).padStart(64, "0")}` as Hex;
