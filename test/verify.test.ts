import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { MAX_SUB_LIFETIME_SEC, MAX_TAG_KEYS, verifySub } from "../src/core.ts";
import { account, NOW, pushSub, signedRecord } from "./helpers.ts";

describe("verifySub", () => {
  it("accepts a subscription signed by the author", async () => {
    const me = account();
    const rec = await verifySub(await signedRecord(me, { dev: "0x000000000000000000000000000000d1", l: "en", h: 1 }), { now: NOW });
    assert.ok(rec);
    assert.equal(rec.a, me.address);
    assert.equal(rec.dev, "0x000000000000000000000000000000d1");
    assert.deepEqual(rec.sub, pushSub());
    assert.equal(rec.l, "en");
    assert.equal(rec.h, 1);
  });

  it("accepts a subscription signed by a valid session key", async () => {
    const me = account();
    const raw = await signedRecord(me, {}, { session: { key: account(), expiry: BigInt(NOW + 3600) } });
    const rec = await verifySub(raw, { now: NOW });
    assert.equal(rec?.a, me.address);
  });

  it("rejects an expired session key", async () => {
    const raw = await signedRecord(account(), {}, { session: { key: account(), expiry: BigInt(NOW - 1) } });
    assert.equal(await verifySub(raw, { now: NOW }), null);
  });

  it("rejects a session delegated by someone else", async () => {
    const me = account();
    const other = account();
    const raw = await signedRecord(other, {}, { author: me.address, session: { key: account(), expiry: BigInt(NOW + 3600) } });
    assert.equal(await verifySub(raw, { now: NOW }), null);
  });

  it("rejects a signature from another account", async () => {
    const victim = account();
    const raw = await signedRecord(account(), {}, { author: victim.address });
    assert.equal(await verifySub(raw, { now: NOW }), null);
  });

  it("rejects a tampered body", async () => {
    const raw = await signedRecord(account(), {});
    const tampered = { ...raw, b: raw.b.replace("fcm.googleapis.com", "updates.push.services.mozilla.com") };
    assert.equal(await verifySub(tampered, { now: NOW }), null);
  });

  it("rejects malformed inputs", async () => {
    assert.equal(await verifySub(null), null);
    assert.equal(await verifySub({ b: "not json", s: "0x00000000000000000000000000000000" }), null);
    const raw = await signedRecord(account(), {});
    assert.equal(await verifySub({ ...raw, s: "0x1234" }), null);
    assert.equal(await verifySub({ b: JSON.stringify({ v: 2 }), s: raw.s }), null);
  });

  it("only accepts https push endpoints, unless http is explicitly allowed", async () => {
    const me = account();
    const raw = await signedRecord(me, { sub: { ...pushSub(), endpoint: "http://localhost/push" } });
    assert.equal(await verifySub(raw, { now: NOW }), null);
    assert.ok(await verifySub(raw, { now: NOW, allowHttp: true }));
  });

  it("only sends to known Web Push services, to prevent SSRF", async () => {
    const me = account();
    for (const endpoint of ["https://fcm.googleapis.com/fcm/send/x", "https://updates.push.services.mozilla.com/wpush/v2/x", "https://web.push.apple.com/x", "https://wns2-par02p.notify.windows.com/w/?token=x"]) {
      assert.ok(await verifySub(await signedRecord(me, { sub: { ...pushSub(), endpoint } }), { now: NOW }), endpoint);
    }
    for (const endpoint of [
      "https://169.254.169.254/latest/meta-data",
      "https://localhost/x",
      "https://internal.example.org/x",
      "https://fcm.googleapis.com.evil.org/x",
      "https://evilfcm.googleapis.com.attacker.io/x",
      "https://user:pass@fcm.googleapis.com/x",
      "https://fcm.googleapis.com:8443/x",
    ]) {
      assert.equal(await verifySub(await signedRecord(me, { sub: { ...pushSub(), endpoint } }), { now: NOW }), null, endpoint);
    }
    const custom = await signedRecord(me, { sub: { ...pushSub(), endpoint: "https://push.my-browser.example/x" } });
    assert.equal(await verifySub(custom, { now: NOW }), null);
    assert.ok(await verifySub(custom, { now: NOW, extraHosts: ["push.my-browser.example"] }));
  });

  it("rejects a subscription without push keys", async () => {
    const raw = await signedRecord(account(), { sub: { endpoint: "https://fcm.googleapis.com/fcm/send/x", keys: { p256dh: "", auth: "" } } });
    assert.equal(await verifySub(raw, { now: NOW }), null);
  });

  it("turns a null subscription into an unsubscribe record", async () => {
    const me = account();
    const rec = await verifySub(await signedRecord(me, { dev: "0x000000000000000000000000000000d2", sub: null }), { now: NOW });
    assert.deepEqual(rec, { a: me.address, dev: "0x000000000000000000000000000000d2", sub: null, exp: 0, tk: [] });
  });

  it("caps the lifetime and keeps well-formed tag keys", async () => {
    const tk = Array.from({ length: 3 }, (_, i) => `0x${i.toString(16).padStart(32, "0")}`);
    const rec = await verifySub(await signedRecord(account(), { exp: NOW + 10 * 365 * 86_400, l: "de", tk: [...tk, tk[0]] }), { now: NOW });
    assert.equal(rec?.exp, NOW + MAX_SUB_LIFETIME_SEC);
    assert.equal(rec?.l, "fr");
    assert.deepEqual(rec?.tk, tk);
  });

  it("rejects malformed records instead of storing them", async () => {
    const reject = async (record: Record<string, unknown>) =>
      assert.equal(await verifySub(await signedRecord(account(), record as never), { now: NOW }), null, JSON.stringify(record));
    await reject({ tk: ["0x1234"] });
    await reject({ tk: [42] });
    await reject({ tk: "0x" + "0".repeat(32) });
    await reject({ tk: Array.from({ length: MAX_TAG_KEYS + 1 }, (_, i) => `0x${i.toString(16).padStart(32, "0")}`) });
    await reject({ exp: "soon" });
    await reject({ exp: Number.NaN });
    await reject({ exp: NOW - 1 });
    await reject({ dev: "0x01" });
    await reject({ dev: { $gt: "" } });
    await reject({ sub: { endpoint: "https://fcm.googleapis.com/fcm/send/x", keys: { p256dh: "a b", auth: "x" } } });
    await reject({ sub: { endpoint: "https://fcm.googleapis.com/fcm/send/x", keys: { p256dh: 1, auth: "x" } } });
  });
});
