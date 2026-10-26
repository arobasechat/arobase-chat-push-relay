import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { toHex, type Address, type Hex } from "viem";
import { createHash } from "node:crypto";
import { collect, tagAt, tagsForRange, type Clients, type Event } from "../src/core.ts";
import { addressTarget, KIND } from "../src/protocol.ts";
import { account, config, emptyData, fakeClient, id, sub, type FakeLog } from "./helpers.ts";

const CONTENT = "0x00000000000000000000000000000000000000c2";
const INBOX = "0x00000000000000000000000000000000000000c3";
const SOCIAL = "0x00000000000000000000000000000000000000c1";

function setup(opts: { social?: FakeLog[]; content?: FakeLog[]; posts?: Record<string, Hex[]>; params?: Record<string, unknown>; subs?: ReturnType<typeof sub>[] }) {
  const social = fakeClient({ latest: 10n, logs: opts.social });
  const content = fakeClient({
    latest: 10n,
    logs: opts.content,
    read: {
      page: (args) => {
        const author = `0x${String(args[1]).slice(26)}`.toLowerCase();
        const ids = opts.posts?.[author] ?? [];
        return [ids, ids.map(() => ({ kind: 0 })), BigInt(ids.length)];
      },
    },
  });
  const clients: Clients = new Map([
    [100, social],
    [5042, content],
  ]);
  const data = emptyData({ subs: Object.fromEntries((opts.subs ?? []).map((s) => [`${s.a.toLowerCase()}:${s.dev}`, s])) });
  for (const k of ["notify:5042:" + CONTENT, "follow", "like", "invite:5042", "dm:5042"]) data.cursors[k] = "1";
  const cfg = config({ params: opts.params ?? {} });
  return { clients, data, cfg };
}

const strip = (events: Event[]) => events.map(({ p: _p, ...e }) => e);
const sorted = (events: Event[]) => [...strip(events)].sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));

describe("collect", () => {
  it("returns nothing without subscribers", async () => {
    const { clients, data, cfg } = setup({});
    assert.deepEqual(await collect(data, cfg, clients, { maxSpan: 100n }), []);
  });

  it("maps Content.Notify reasons to notification types, only for subscribers", async () => {
    const me = account().address;
    const other = account().address;
    const from = account().address;
    const notify = (to: Address, reason: number, n: number): FakeLog => ({ event: "Notify", address: CONTENT, blockNumber: 5n, args: { to, from, reason, postId: id(n) } });
    const { clients, data, cfg } = setup({
      subs: [sub(me)],
      content: [notify(me, 1, 1), notify(me, 2, 2), notify(me, 3, 3), notify(me, 4, 4), notify(me, 5, 5), notify(me, 9, 6), notify(other, 1, 7)],
    });
    const events = await collect(data, cfg, clients, { maxSpan: 100n });
    assert.deepEqual(
      events.map((e) => [e.t, e.post]),
      [
        ["mention", id(1)],
        ["reply", id(2)],
        ["note", id(3)],
        ["repost", id(4)],
        ["quote", id(5)],
      ],
    );
  });

  it("notifies new followers, but not unfollows or self-follows", async () => {
    const me = account().address;
    const fan = account().address;
    const act = (author: Address, value: number): FakeLog => ({ event: "Acted", address: SOCIAL, blockNumber: 5n, args: { author, kind: KIND.FOLLOW, target: addressTarget(me), value } });
    const { clients, data, cfg } = setup({ subs: [sub(me)], social: [act(fan, 1), act(fan, 0), act(me, 1)] });
    const events = strip(await collect(data, cfg, clients, { maxSpan: 100n }));
    assert.deepEqual(events, [{ to: me.toLowerCase(), t: "follow", from: fan }]);
  });

  it("notifies likes on the subscriber's recent posts", async () => {
    const me = account().address;
    const fan = account().address;
    const post = id(42);
    const like = (author: Address, target: Hex, value: number): FakeLog => ({ event: "Acted", address: SOCIAL, blockNumber: 6n, args: { author, kind: KIND.REACT, target, value } });
    const { clients, data, cfg } = setup({
      subs: [sub(me)],
      posts: { [me.toLowerCase()]: [post] },
      social: [like(fan, post, 1), like(fan, id(43), 1), like(me, post, 1), like(fan, post, -1)],
    });
    const events = strip(await collect(data, cfg, clients, { maxSpan: 100n }));
    assert.deepEqual(events, [{ to: me.toLowerCase(), t: "like", from: fan, post }]);
  });

  it("broadcasts posts of the platform account to every subscriber with an excerpt", async () => {
    const platform = account().address;
    const a = account().address;
    const b = account().address;
    const { clients, data, cfg } = setup({
      subs: [sub(a), sub(b), sub(platform)],
      params: { platform },
      content: [{ event: "Message", address: CONTENT, blockNumber: 7n, args: { id: id(9), author: platform, kind: KIND.POST, payload: toHex(JSON.stringify({ text: "Maintenance ce soir" })) } }],
    });
    data.cursors[`platform:5042:${platform.toLowerCase()}`] = "1";
    const events = await collect(data, cfg, clients, { maxSpan: 100n });
    assert.deepEqual(
      sorted(events),
      sorted([a, b].map((to) => ({ to: to.toLowerCase() as Address, t: "announcement", from: platform, post: id(9), x: "Maintenance ce soir" }))),
    );
  });

  it("notifies direct messages through rotating tags, without learning conversations", async () => {
    const me = account().address;
    const key = `0x${"ab".repeat(16)}` as Hex;
    const other = `0x${"cd".repeat(16)}` as Hex;
    const { clients, data, cfg } = setup({
      subs: [sub(me, { tk: [key] })],
      content: [
        { event: "Encrypted", address: INBOX, blockNumber: 4n, args: { tag: tagAt(key, 0n) } },
        { event: "Encrypted", address: INBOX, blockNumber: 4n, args: { tag: tagAt(other, 0n) } },
        { event: "Encrypted", address: INBOX, blockNumber: 4n, args: { tag: tagAt(key, 7n) } },
      ],
    });
    const events = await collect(data, cfg, clients, { maxSpan: 100n });
    assert.deepEqual(sorted(events), sorted([{ to: me.toLowerCase() as Address, t: "dm" }]));
  });

  it("derives the same tags as the app for every bucket a range touches", () => {
    const key = `0x${"01".repeat(16)}` as Hex;
    assert.equal(tagAt(key, 244n), "0x" + createHash("sha256").update(Buffer.concat([Buffer.from("01".repeat(16), "hex"), Buffer.from("00000000000000f4", "hex")])).digest("hex"));
    assert.deepEqual(tagsForRange([key], 4096n * 3n + 5n, 4096n * 4n + 1n), [tagAt(key, 2n), tagAt(key, 3n), tagAt(key, 4n)]);
  });

  it("attaches an onchain proof (chain, transaction, log index) to every event", async () => {
    const me = account().address;
    const fan = account().address;
    const tx = id(777);
    const { clients, data, cfg } = setup({
      subs: [sub(me, { tk: [`0x${"ab".repeat(16)}`] })],
      social: [{ event: "Acted", address: SOCIAL, blockNumber: 5n, transactionHash: tx, logIndex: 3, args: { author: fan, kind: KIND.FOLLOW, target: addressTarget(me), value: 1 } }],
      content: [
        { event: "Notify", address: CONTENT, blockNumber: 6n, transactionHash: id(888), logIndex: 1, args: { to: me, from: fan, reason: 1, postId: id(1) } },
        { event: "Encrypted", address: INBOX, blockNumber: 7n, transactionHash: id(999), logIndex: 0, args: { tag: tagAt(`0x${"ab".repeat(16)}`, 0n) } },
      ],
    });
    const events = await collect(data, cfg, clients, { maxSpan: 100n });
    const byType = Object.fromEntries(events.map((e) => [e.t, e.p]));
    assert.deepEqual(byType.follow, { c: 100, tx, i: 3 });
    assert.deepEqual(byType.mention, { c: 5042, tx: id(888), i: 1 });
    assert.deepEqual(byType.dm, { c: 5042, tx: id(999), i: 0 });
  });

  it("keeps the other sources working when one RPC fails", async () => {
    const me = account().address;
    const fan = account().address;
    const { clients, data, cfg } = setup({
      subs: [sub(me)],
      social: [{ event: "Acted", address: SOCIAL, blockNumber: 5n, args: { author: fan, kind: KIND.FOLLOW, target: addressTarget(me), value: 1 } }],
    });
    clients.set(5042, fakeClient({ latest: 10n, failRanges: () => true, read: { page: () => [[], [], 0n] } }));
    const errors: unknown[] = [];
    const events = strip(await collect(data, cfg, clients, { maxSpan: 100n, onError: (e) => errors.push(e) }));
    assert.deepEqual(events, [{ to: me.toLowerCase(), t: "follow", from: fan }]);
    assert.ok(errors.length >= 1);
    assert.equal(data.cursors[`notify:5042:${CONTENT}`], "1");
    assert.equal(data.cursors.follow, "11");
  });
});
