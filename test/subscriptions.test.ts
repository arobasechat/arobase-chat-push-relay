import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { applySubscription, MAX_DEVICES, openSubscription, pruneExpired, syncSubscriptions, type Clients, type Sub } from "../src/core.ts";
import { account, config, emptyData, fakeClient, NOW, relayKeys, seal, signedRecord, sub } from "./helpers.ts";

const PUSH = "0x00000000000000000000000000000000000000a1";

describe("openSubscription", () => {
  it("decrypts with the current key or a rotated old key", async () => {
    const current = relayKeys();
    const old = relayKeys();
    const raw = await signedRecord(account(), {});
    assert.deepEqual(openSubscription([current.secret, old.secret], seal(current.pub, raw)), raw);
    assert.deepEqual(openSubscription([current.secret, old.secret], seal(old.pub, raw)), raw);
  });

  it("returns null for a ciphertext sealed to another relay or corrupted", async () => {
    const mine = relayKeys();
    const raw = await signedRecord(account(), {});
    assert.equal(openSubscription([mine.secret], seal(relayKeys().pub, raw)), null);
    assert.equal(openSubscription([mine.secret], "0xdeadbeef"), null);
  });
});

describe("applySubscription", () => {
  it("adds, updates, then removes a device", () => {
    const a = account().address;
    const subs: Record<string, Sub> = {};
    assert.equal(applySubscription(subs, sub(a, { dev: "0x00000000000000000000000000000001" })), "added");
    assert.equal(applySubscription(subs, sub(a, { dev: "0x00000000000000000000000000000001", l: "en" })), "updated");
    assert.equal(subs[`${a.toLowerCase()}:0x00000000000000000000000000000001`].l, "en");
    assert.equal(applySubscription(subs, { ...sub(a, { dev: "0x00000000000000000000000000000001" }), sub: null }), "removed");
    assert.deepEqual(subs, {});
    assert.equal(applySubscription(subs, { ...sub(a, { dev: "0x00000000000000000000000000000009" }), sub: null }), "unknown");
  });

  it(`keeps at most ${MAX_DEVICES} devices per account, evicting the oldest`, () => {
    const a = account().address;
    const subs: Record<string, Sub> = {};
    for (let i = 0; i < MAX_DEVICES + 2; i++) applySubscription(subs, sub(a, { dev: `0x${(i + 1).toString(16).padStart(32, "0")}` }));
    const keys = Object.keys(subs);
    assert.equal(keys.length, MAX_DEVICES);
    assert.ok(!keys.includes(`${a.toLowerCase()}:0x00000000000000000000000000000001`));
    assert.ok(keys.includes(`${a.toLowerCase()}:0x0000000000000000000000000000000c`));
  });
});

describe("pruneExpired", () => {
  it("removes only expired subscriptions", () => {
    const subs: Record<string, Sub> = { old: sub(account().address, { exp: NOW - 1 }), fresh: sub(account().address, { exp: NOW + 1 }) };
    assert.equal(pruneExpired(subs, NOW), 1);
    assert.deepEqual(Object.keys(subs), ["fresh"]);
  });
});

describe("syncSubscriptions", () => {
  it("backfills from the deploy block, then follows new Subscribed events", async () => {
    const keys = relayKeys();
    const alice = account();
    const bob = account();
    const logs = [
      { event: "Subscribed", blockNumber: 12n, args: { relayId: 0n, ciphertext: seal(keys.pub, await signedRecord(alice, { dev: "0x000000000000000000000000000000a1" })) } },
      { event: "Subscribed", blockNumber: 15n, args: { relayId: 1n, ciphertext: seal(keys.pub, await signedRecord(bob, { dev: "0x000000000000000000000000000000b1" })) } },
      { event: "Subscribed", blockNumber: 18n, args: { relayId: 0n, ciphertext: seal(relayKeys().pub, await signedRecord(bob, { dev: "0x000000000000000000000000000000b2" })) } },
    ];
    const client = fakeClient({ latest: 20n, logs });
    const clients: Clients = new Map([[100, client]]);
    const cfg = config({ params: { push: { chainId: 100, address: PUSH, deployBlock: 10 } } });
    const data = emptyData({ encSecret: keys.secret });

    const first = await syncSubscriptions(data, cfg, clients, { maxSpan: 5n, now: NOW });
    assert.deepEqual(first, [{ address: alice.address, change: "added" }]);
    assert.deepEqual(Object.keys(data.subs), [`${alice.address.toLowerCase()}:0x000000000000000000000000000000a1`]);
    assert.equal(data.cursors[`subs:${PUSH}:0`], "21");

    client.latest = 30n;
    logs.push({ event: "Subscribed", blockNumber: 25n, args: { relayId: 0n, ciphertext: seal(keys.pub, await signedRecord(alice, { dev: "0x000000000000000000000000000000a1", sub: null })) } });
    const second = await syncSubscriptions(data, cfg, clients, { maxSpan: 5n, now: NOW });
    assert.deepEqual(second, [{ address: alice.address, change: "removed" }]);
    assert.deepEqual(data.subs, {});
    assert.equal(data.cursors[`subs:${PUSH}:0`], "31");
  });

  it("ignores forged subscriptions", async () => {
    const keys = relayKeys();
    const victim = account();
    const forged = await signedRecord(account(), { dev: "0x000000000000000000000000000000ff" }, { author: victim.address });
    const client = fakeClient({ latest: 5n, logs: [{ event: "Subscribed", blockNumber: 3n, args: { relayId: 0n, ciphertext: seal(keys.pub, forged) } }] });
    const data = emptyData({ encSecret: keys.secret });
    const cfg = config({ params: { push: { chainId: 100, address: PUSH, deployBlock: 0 } } });
    assert.deepEqual(await syncSubscriptions(data, cfg, new Map([[100, client]]), { maxSpan: 100n, now: NOW }), []);
    assert.deepEqual(data.subs, {});
  });
});
