import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { Address } from "viem";
import { deliver, groupEvents, handles, payloadFor, urgencyOf, type Clients, type PushSubscription, type Sender } from "../src/core.ts";
import { account, config, emptyData, fakeClient, id, sub } from "./helpers.ts";

const recorder = (statusFor: (endpoint: string) => number = () => 201) => {
  const sent: { endpoint: string; payload: Record<string, unknown>; urgency: string }[] = [];
  const send: Sender = async (s: PushSubscription, payload, urgency) => {
    sent.push({ endpoint: s.endpoint, payload: JSON.parse(payload), urgency });
    return statusFor(s.endpoint);
  };
  return { sent, send };
};

describe("groupEvents", () => {
  it("merges identical notifications and counts them", () => {
    const me = account().address;
    const a = account().address;
    const b = account().address;
    const groups = groupEvents([
      { to: me, t: "like", from: a, post: id(1) },
      { to: me, t: "like", from: b, post: id(1) },
      { to: me, t: "like", from: a, post: id(2) },
      { to: me, t: "dm" },
      { to: me, t: "dm" },
    ]);
    assert.deepEqual(
      groups.map((g) => [g.t, g.post, g.n, g.from]),
      [
        ["like", id(1), 2, a],
        ["like", id(2), 1, a],
        ["dm", undefined, 2, undefined],
      ],
    );
  });
});

describe("payload", () => {
  it("marks direct messages and mentions as high urgency", () => {
    assert.equal(urgencyOf("dm"), "high");
    assert.equal(urgencyOf("mention"), "high");
    assert.equal(urgencyOf("like"), "normal");
  });

  it("carries what the service worker needs, and nothing private", () => {
    const me = account().address;
    const from = account().address;
    const s = sub(me, { h: 1, l: "en" });
    const proof = { c: 5042, tx: id(6), i: 2 };
    const p = JSON.parse(payloadFor({ to: me, t: "reply", from, post: id(5), n: 3, p: proof }, s, "bob"));
    assert.deepEqual(p, { t: "reply", from, name: "bob", post: id(5), n: 3, h: 1, lang: "en", p: proof });
    assert.equal(JSON.stringify(p).includes(s.sub.keys.auth), false);
  });
});

describe("deliver", () => {
  it("sends to every device of the recipient, with handles", async () => {
    const me = account().address;
    const other = account().address;
    const from = account().address;
    const data = emptyData({
      subs: {
        [`${me.toLowerCase()}:0x00000000000000000000000000000001`]: sub(me, { dev: "0x00000000000000000000000000000001", sub: { endpoint: "https://push.example.org/phone", keys: { p256dh: "p", auth: "a" } } }),
        [`${me.toLowerCase()}:0x00000000000000000000000000000002`]: sub(me, { dev: "0x00000000000000000000000000000002", sub: { endpoint: "https://push.example.org/laptop", keys: { p256dh: "p", auth: "a" } } }),
        [`${other.toLowerCase()}:0x00000000000000000000000000000001`]: sub(other),
      },
    });
    const { sent, send } = recorder();
    const result = await deliver(data, [{ to: me, t: "mention", from, post: id(1), n: 1 }], new Map([[from.toLowerCase(), "alice"]]), send);
    assert.equal(result.sent, 2);
    assert.deepEqual(sent.map((s) => s.endpoint).sort(), ["https://push.example.org/laptop", "https://push.example.org/phone"]);
    assert.ok(sent.every((s) => s.payload.name === "alice" && s.urgency === "high"));
  });

  it("drops subscriptions the push service reports as gone, keeps transient failures", async () => {
    const me = account().address;
    const data = emptyData({
      subs: {
        gone: sub(me, { dev: "0x00000000000000000000000000000001", sub: { endpoint: "https://push.example.org/gone", keys: { p256dh: "p", auth: "a" } } }),
        missing: sub(me, { dev: "0x00000000000000000000000000000002", sub: { endpoint: "https://push.example.org/missing", keys: { p256dh: "p", auth: "a" } } }),
        flaky: sub(me, { dev: "0x00000000000000000000000000000003", sub: { endpoint: "https://push.example.org/flaky", keys: { p256dh: "p", auth: "a" } } }),
      },
    });
    const status: Record<string, number> = { gone: 410, missing: 404, flaky: 503 };
    const { send } = recorder((e) => status[e.split("/").at(-1)!]);
    const result = await deliver(data, [{ to: me, t: "follow", n: 1 }], new Map(), send);
    assert.equal(result.sent, 0);
    assert.equal(result.expired.length, 2);
    assert.deepEqual(result.failed, [{ endpoint: "https://push.example.org/flaky", status: 503 }]);
    assert.deepEqual(Object.keys(data.subs), ["flaky"]);
  });
});

describe("handles", () => {
  it("resolves usernames from the Names contract, ignoring empty ones", async () => {
    const a = account().address;
    const b = account().address;
    const client = fakeClient({ read: { namesOf: (args) => (args[0] as Address[]).map((x) => (x === a ? "alice" : "")) } });
    const clients: Clients = new Map([[100, client]]);
    const names = await handles(config({ params: { names: "0x00000000000000000000000000000000000000d1" } }), clients, [a, b]);
    assert.deepEqual([...names], [[a.toLowerCase(), "alice"]]);
  });

  it("returns nothing when usernames are not enabled or the call fails", async () => {
    const a = account().address;
    const clients: Clients = new Map([[100, fakeClient({})]]);
    assert.equal((await handles(config(), clients, [a])).size, 0);
    assert.equal((await handles(config({ params: { names: "0x00000000000000000000000000000000000000d1" } }), clients, [a])).size, 0);
  });
});
