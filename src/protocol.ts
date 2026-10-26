import { keccak256, toBytes, toHex, type Address, type Hex, type LocalAccount, concat, numberToHex } from "viem";

export const KIND = {
  POST: 0,
  COMMENT: 1,
  NOTE: 2,
  PROFILE: 3,
  REACT: 10,
  FOLLOW: 11,
  MOD_VOTE: 12,
  ENC_KEY: 13,
  REVOKE_SESSION: 14,
  RATE_NOTE: 15,
  ROLE: 20,
} as const;

export const domain = { name: "arobase.chat", version: "1" } as const;

export const types = {
  Message: [
    { name: "author", type: "address" },
    { name: "kind", type: "uint8" },
    { name: "parentId", type: "bytes32" },
    { name: "ts", type: "uint64" },
    { name: "payloadHash", type: "bytes32" },
  ],
  Action: [
    { name: "author", type: "address" },
    { name: "kind", type: "uint8" },
    { name: "target", type: "bytes32" },
    { name: "value", type: "int8" },
    { name: "nonce", type: "uint64" },
  ],
  Session: [
    { name: "key", type: "address" },
    { name: "expiry", type: "uint64" },
  ],
} as const;

export const ZERO32 = `0x${"0".repeat(64)}` as Hex;

export type SignedMessage = {
  id: Hex;
  author: Address;
  kind: number;
  parentId: Hex;
  ts: number;
  payload: Hex;
  sig: Hex;
};

export function encodePayload(body: Record<string, unknown>): Hex {
  return toHex(toBytes(JSON.stringify(body)));
}

export async function signMessage(
  account: LocalAccount,
  kind: number,
  body: Record<string, unknown>,
  parentId: Hex = ZERO32,
  ts = Math.floor(Date.now() / 1000),
): Promise<SignedMessage> {
  const payload = encodePayload({ v: 1, ...body, ...(parentId !== ZERO32 ? { parentId } : {}), ts });
  const sig = await account.signTypedData({
    domain,
    types,
    primaryType: "Message",
    message: { author: account.address, kind, parentId, ts: BigInt(ts), payloadHash: keccak256(payload) },
  });
  return { id: keccak256(sig), author: account.address, kind, parentId, ts, payload, sig };
}

export async function signAction(
  account: LocalAccount,
  kind: number,
  target: Hex,
  value: number,
  nonce: bigint,
) {
  const sig = await account.signTypedData({
    domain,
    types,
    primaryType: "Action",
    message: { author: account.address, kind, target, value, nonce },
  });
  return { author: account.address, kind, target, value, nonce, sig };
}

export async function signSession(identity: LocalAccount, key: Address, expiry: bigint): Promise<Hex> {
  const sig = await identity.signTypedData({
    domain,
    types,
    primaryType: "Session",
    message: { key, expiry },
  });
  return concat([sig, numberToHex(expiry, { size: 8 })]);
}

export const addressTarget = (a: Address): Hex => `0x${a.slice(2).toLowerCase().padStart(64, "0")}` as Hex;
