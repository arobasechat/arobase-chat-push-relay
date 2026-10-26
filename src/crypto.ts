import { x25519 } from "@noble/curves/ed25519.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { bytesToHex, concat, hexToBytes, keccak256, toHex, type Address, type Hex } from "viem";

const te = new TextEncoder();
const td = new TextDecoder();

export const derive = (ikm: Uint8Array, info: string, len = 32) => hkdf(sha256, ikm, undefined, te.encode(info), len);

export const encKeypairFromSeed = (seed: Uint8Array) => {
  const secretKey = derive(seed, "arobase:x25519");
  return { secretKey, publicKey: x25519.getPublicKey(secretKey) };
};

export const inviteTag = (encPub: Uint8Array): Hex => keccak256(concat([toHex("arobase:invite"), bytesToHex(encPub)]));

export const convIdOf = (convKey: Uint8Array): Hex => keccak256(concat([toHex("arobase:conv"), bytesToHex(convKey)]));

export const directConvKey = (mySecret: Uint8Array, theirPub: Uint8Array) =>
  derive(x25519.getSharedSecret(mySecret, theirPub), "arobase:conv:1to1");

export type EnvelopeBody = {
  t: "dm" | "group";
  from: Address;
  fromEnc: Hex;
  convKey: Hex;
  convId: Hex;
  epoch: number;
  name?: string;
  members?: Address[];
  mac?: Hex;
};

const macInput = (convKey: Hex, convId: Hex, epoch: number) => te.encode(`${convKey}|${convId}|${epoch}`);

export function envelopeMac(mySecret: Uint8Array, otherPub: Uint8Array, body: EnvelopeBody): Hex {
  const k = derive(x25519.getSharedSecret(mySecret, otherPub), "arobase:envelope-auth");
  return bytesToHex(sha256(new Uint8Array([...k, ...macInput(body.convKey, body.convId, body.epoch)])));
}

export function checkEnvelope(mySecret: Uint8Array, body: EnvelopeBody): boolean {
  if (!body.mac) return false;
  try {
    return envelopeMac(mySecret, hexToBytes(body.fromEnc), body) === body.mac;
  } catch {
    return false;
  }
}

export function sealEnvelope(senderSecret: Uint8Array, recipientPub: Uint8Array, content: EnvelopeBody): Hex {
  const body = { ...content, mac: envelopeMac(senderSecret, recipientPub, content) };
  const eph = x25519.utils.randomSecretKey();
  const ephPub = x25519.getPublicKey(eph);
  const key = derive(x25519.getSharedSecret(eph, recipientPub), "arobase:envelope");
  const nonce = randomBytes(24);
  const ct = xchacha20poly1305(key, nonce).encrypt(te.encode(JSON.stringify(body)));
  return bytesToHex(new Uint8Array([...ephPub, ...nonce, ...ct]));
}

export function openEnvelope(mySecret: Uint8Array, envelope: Hex): EnvelopeBody | null {
  try {
    const bytes = hexToBytes(envelope);
    const key = derive(x25519.getSharedSecret(mySecret, bytes.slice(0, 32)), "arobase:envelope");
    const pt = xchacha20poly1305(key, bytes.slice(32, 56)).decrypt(bytes.slice(56));
    return JSON.parse(td.decode(pt)) as EnvelopeBody;
  } catch {
    return null;
  }
}

export function encryptFor(convKey: Uint8Array, inner: unknown): Hex {
  const nonce = randomBytes(24);
  const ct = xchacha20poly1305(convKey, nonce).encrypt(te.encode(JSON.stringify(inner)));
  return bytesToHex(new Uint8Array([...nonce, ...ct]));
}

export function openSealed<T>(mySecret: Uint8Array, info: string, sealed: Hex): T | null {
  try {
    const bytes = hexToBytes(sealed);
    const key = derive(x25519.getSharedSecret(mySecret, bytes.slice(0, 32)), info);
    const pt = xchacha20poly1305(key, bytes.slice(32, 56)).decrypt(bytes.slice(56));
    return JSON.parse(td.decode(pt)) as T;
  } catch {
    return null;
  }
}

export function sealTo(recipientPub: Uint8Array, info: string, content: unknown): Hex {
  const eph = x25519.utils.randomSecretKey();
  const key = derive(x25519.getSharedSecret(eph, recipientPub), info);
  const nonce = randomBytes(24);
  const ct = xchacha20poly1305(key, nonce).encrypt(te.encode(JSON.stringify(content)));
  return bytesToHex(new Uint8Array([...x25519.getPublicKey(eph), ...nonce, ...ct]));
}
