import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { chunk, excerpt, scanRange } from "../src/core.ts";
import { toHex } from "viem";
import { fakeClient } from "./helpers.ts";

const fetchRange = (calls: [bigint, bigint][], fail?: (from: bigint, to: bigint) => boolean) => async (from: bigint, to: bigint) => {
  if (fail?.(from, to)) throw new Error("too many blocks");
  calls.push([from, to]);
  return [`${from}-${to}`];
};

describe("scanRange", () => {
  it("starts at the head on first run, without replaying history", async () => {
    const cursors: Record<string, string> = {};
    const calls: [bigint, bigint][] = [];
    assert.deepEqual(await scanRange(cursors, "k", fakeClient({ latest: 1000n }), fetchRange(calls), 100n), []);
    assert.equal(cursors.k, "1001");
    assert.equal(calls.length, 0);
  });

  it("covers every block exactly once in spans, then advances the cursor", async () => {
    const cursors: Record<string, string> = { k: "1001" };
    const calls: [bigint, bigint][] = [];
    const out = await scanRange(cursors, "k", fakeClient({ latest: 1250n }), fetchRange(calls), 100n);
    assert.deepEqual(calls, [
      [1001n, 1100n],
      [1101n, 1200n],
      [1201n, 1250n],
    ]);
    assert.equal(out.length, 3);
    assert.equal(cursors.k, "1251");
  });

  it("does nothing when no new block", async () => {
    const cursors: Record<string, string> = { k: "51" };
    const calls: [bigint, bigint][] = [];
    assert.deepEqual(await scanRange(cursors, "k", fakeClient({ latest: 50n }), fetchRange(calls), 100n), []);
    assert.equal(calls.length, 0);
  });

  it("shrinks the span when the RPC refuses a range, and keeps going", async () => {
    const cursors: Record<string, string> = { k: "1" };
    const calls: [bigint, bigint][] = [];
    await scanRange(cursors, "k", fakeClient({ latest: 200n }), fetchRange(calls, (f, t) => t - f + 1n > 50n), 200n);
    assert.ok(calls.every(([f, t]) => t - f + 1n <= 50n));
    assert.equal(calls[0][0], 1n);
    assert.equal(calls.at(-1)?.[1], 200n);
    assert.equal(cursors.k, "201");
  });

  it("gives up without moving the cursor when even small ranges fail", async () => {
    const cursors: Record<string, string> = { k: "1" };
    await assert.rejects(scanRange(cursors, "k", fakeClient({ latest: 200n }), fetchRange([], () => true), 64n));
    assert.equal(cursors.k, "1");
  });
});

describe("helpers", () => {
  it("chunk splits lists", () => {
    assert.deepEqual(chunk([1, 2, 3, 4, 5], 2), [[1, 2], [3, 4], [5]]);
    assert.deepEqual(chunk([], 50), []);
  });

  it("excerpt extracts and shortens the post text", () => {
    assert.equal(excerpt(toHex(JSON.stringify({ text: "  hello\n\n world " }))), "hello world");
    const long = excerpt(toHex(JSON.stringify({ text: "x".repeat(300) })));
    assert.equal(long?.length, 140);
    assert.ok(long?.endsWith("…"));
    assert.equal(excerpt(toHex(JSON.stringify({ media: [] }))), undefined);
    assert.equal(excerpt("0xzz"), undefined);
  });
});
