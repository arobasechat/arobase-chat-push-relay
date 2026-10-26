import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { parseArgs } from "node:util";
import { x25519 } from "@noble/curves/ed25519.js";
import { randomBytes } from "@noble/hashes/utils.js";
import webpush from "web-push";
import { bytesToHex, createPublicClient, createWalletClient, defineChain, fallback, hexToBytes, hexToString, http, parseEventLogs, type Address, type Hex, type PublicClient } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { pushRelaysAbi, registryAbi } from "./abi.ts";
import {
  collect,
  deliver,
  groupEvents,
  handles,
  lc,
  pushParamOf,
  short,
  syncSubscriptions,
  type Config,
  type Data,
  type Sender,
} from "./core.ts";
import { DATA_DIR, registryLocation as locate } from "./paths.ts";

const TICK_MS = Number(process.env.RELAY_TICK_MS ?? 12_000);
const MAX_SPAN = BigInt(process.env.RELAY_MAX_SPAN ?? 5_000);
const ALLOW_HTTP = !!process.env.RELAY_ALLOW_HTTP;
const EXTRA_PUSH_HOSTS = (process.env.RELAY_EXTRA_PUSH_HOSTS ?? "").split(",").filter(Boolean);

const { positionals, values: flags } = parseArgs({
  allowPositionals: true,
  options: {
    network: { type: "string", default: "mainnet" },
    data: { type: "string" },
    name: { type: "string" },
    info: { type: "string", default: "" },
    contact: { type: "string" },
  },
});
const command = positionals[0] ?? "run";

const dataPath = resolve(flags.data ?? resolve(DATA_DIR, `${flags.network}.json`));

function loadData(): Data {
  if (!existsSync(dataPath)) throw new Error(`Aucune clé de relais : lancez d'abord « pnpm relay init --network ${flags.network} ».`);
  return JSON.parse(readFileSync(dataPath, "utf8"));
}

function saveData(d: Data) {
  mkdirSync(dirname(dataPath), { recursive: true });
  const tmp = `${dataPath}.tmp`;
  writeFileSync(tmp, JSON.stringify(d, null, 2), { mode: 0o600 });
  renameSync(tmp, dataPath);
  chmodSync(dataPath, 0o600);
}

const registryLocation = () => locate(flags.network!);
const vapidHex = (b64: string) => bytesToHex(Buffer.from(b64, "base64url"));
const encPublic = (d: Data) => bytesToHex(x25519.getPublicKey(hexToBytes(d.encSecret)));

const clients = new Map<number, PublicClient>();

function clientFor(chainId: number, rpcs: string[]) {
  let c = clients.get(chainId);
  if (!c) {
    const chain = defineChain({ id: chainId, name: String(chainId), nativeCurrency: { name: "Gas", symbol: "GAS", decimals: 18 }, rpcUrls: { default: { http: rpcs } } });
    c = createPublicClient({ chain, transport: fallback(rpcs.map((u) => http(u, { timeout: 20_000, retryCount: 1, batch: true }))) }) as PublicClient;
    clients.set(chainId, c);
  }
  return c;
}

async function readConfig(registry: Address, rpcs: string[]): Promise<Config> {
  const probe = createPublicClient({ transport: fallback(rpcs.map((u) => http(u, { timeout: 20_000 }))) });
  const registryChainId = await probe.getChainId();
  const reg = clientFor(registryChainId, rpcs);
  const [, social, , chains, keys, values] = await reg.readContract({ address: registry, abi: registryAbi, functionName: "snapshot" });
  const params: Record<string, unknown> = {};
  keys.forEach((k, i) => {
    const key = hexToString(k, { size: 32 }).replace(/\0+$/, "");
    try {
      params[key] = JSON.parse(hexToString(values[i]));
    } catch {
      params[key] = values[i];
    }
  });
  const merged = new Map<number, string[]>([[registryChainId, rpcs]]);
  for (const c of chains) merged.set(Number(c.chainId), [...new Set([...(merged.get(Number(c.chainId)) ?? []), ...c.rpcs])]);
  for (const [id, list] of merged) {
    clients.delete(id);
    clientFor(id, list);
  }
  return {
    params,
    social,
    registryChainId,
    chains: chains.filter((c) => c.active).map((c) => ({ chainId: Number(c.chainId), role: Number(c.role), content: c.content, inbox: c.inbox, rpcs: [...c.rpcs] })),
  };
}

async function init() {
  if (existsSync(dataPath)) throw new Error(`${dataPath} existe déjà. Supprimez-le pour régénérer les clés (les abonnements existants seront perdus).`);
  const { registry, rpcs } = registryLocation();
  const vapid = webpush.generateVAPIDKeys();
  const data: Data = {
    network: flags.network!,
    registry,
    registryRpcs: rpcs,
    contact: flags.contact ?? process.env.RELAY_CONTACT ?? "mailto:relay@arobase.invalid",
    encSecret: bytesToHex(randomBytes(32)),
    oldEncSecrets: [],
    vapidPublic: vapid.publicKey,
    vapidPrivate: vapid.privateKey,
    subs: {},
    cursors: {},
  };
  saveData(data);
  console.log(`Clés du relais créées dans ${dataPath} (permissions 600, à sauvegarder et ne jamais partager).`);
  console.log(`Clé de chiffrement publique : ${encPublic(data)}`);
  console.log(`Clé VAPID publique          : ${vapidHex(data.vapidPublic)}`);
  console.log(`\nÉtape suivante : RELAY_PK=0x… pnpm relay register --network ${flags.network} --name "Mon relais" --info "https://…"`);
}

async function register() {
  const data = loadData();
  const pk = process.env.RELAY_PK as Hex | undefined;
  if (!pk) throw new Error("RELAY_PK requis : la clé de l'adresse opérateur du relais (quelques centimes de gas sur la chain sociale).");
  const cfg = await readConfig(data.registry, data.registryRpcs);
  const p = pushParamOf(cfg);
  if (!p) throw new Error("Le paramètre « push » n'est pas défini dans le Registry.");
  const pub = clients.get(p.chainId)!;
  const account = privateKeyToAccount(pk);
  const wallet = createWalletClient({ account, chain: pub.chain!, transport: () => pub.transport as never });
  const name = flags.name ?? "Relais arobase.chat";
  const args = [name, flags.info ?? "", encPublic(data), vapidHex(data.vapidPublic)] as const;
  const hash =
    data.relayId !== undefined && data.pushContract?.toLowerCase() === p.address.toLowerCase()
      ? await wallet.writeContract({ address: p.address, abi: pushRelaysAbi, functionName: "update", args: [BigInt(data.relayId), ...args, true] })
      : await wallet.writeContract({ address: p.address, abi: pushRelaysAbi, functionName: "register", args });
  const receipt = await pub.waitForTransactionReceipt({ hash });
  const [ev] = parseEventLogs({ abi: pushRelaysAbi, eventName: "RelayChanged", logs: receipt.logs });
  data.relayId = Number(ev.args.id);
  data.pushContract = p.address;
  data.cursors = {};
  saveData(data);
  console.log(`✓ Relais n°${data.relayId} « ${name} » enregistré sur ${p.address} (chain ${p.chainId}).`);
  console.log(`Lancez-le en continu : pnpm relay run --network ${flags.network}`);
}

const send: Sender = async (sub, payload, urgency) => {
  try {
    const req = webpush.generateRequestDetails(sub, payload, { TTL: 86_400, urgency });
    const res = await fetch(req.endpoint, {
      method: req.method,
      headers: req.headers as Record<string, string>,
      body: req.body ? new Uint8Array(req.body) : undefined,
      redirect: "manual",
      signal: AbortSignal.timeout(15_000),
    });
    return res.status;
  } catch {
    return 0;
  }
};

async function tick(data: Data, cfg: Config, postsCache: Map<string, { ids: Hex[]; at: number }>) {
  const changes = await syncSubscriptions(data, cfg, clients, { maxSpan: MAX_SPAN, allowHttp: ALLOW_HTTP, extraHosts: EXTRA_PUSH_HOSTS });
  for (const c of changes) {
    if (c.change === "added") console.log(`  abonnement ${short(c.address)}`);
    else if (c.change === "updated") console.log(`  mise à jour ${short(c.address)}`);
    else if (c.change === "removed") console.log(`  désabonnement ${short(c.address)}`);
  }
  const events = await collect(data, cfg, clients, {
    maxSpan: MAX_SPAN,
    postsCache,
    onError: (err) => console.warn("  lecture partielle :", String(err).split("\n")[0].slice(0, 160)),
  });
  const groups = groupEvents(events);
  if (!groups.length) return;
  const names = await handles(cfg, clients, [...new Set(groups.flatMap((g) => (g.from ? [g.from] : [])))]);
  const result = await deliver(data, groups, names, send);
  for (const a of result.expired) console.log(`  abonnement expiré retiré (${short(a)})`);
  for (const f of result.failed) console.warn(`  envoi échoué (${f.status || "réseau"}) vers ${new URL(f.endpoint).host}`);
  if (result.sent) console.log(`${new Date().toISOString()} · ${events.length} événement(s) · ${result.sent} push envoyé(s)`);
}

async function run() {
  const data = loadData();
  if (data.relayId === undefined) throw new Error(`Relais non enregistré : RELAY_PK=0x… pnpm relay register --network ${flags.network} --name "…"`);
  webpush.setVapidDetails(data.contact, data.vapidPublic, data.vapidPrivate);
  let cfg = await readConfig(data.registry, data.registryRpcs);
  let cfgAt = Date.now();
  const p = pushParamOf(cfg);
  if (!p || lc(p.address) !== lc(data.pushContract ?? "")) throw new Error("Le registre push du Registry ne correspond pas à celui de l'enregistrement. Relancez register.");
  console.log(`Relais n°${data.relayId} actif · ${Object.keys(data.subs).length} abonnement(s) · tick ${TICK_MS / 1000}s`);
  const postsCache = new Map<string, { ids: Hex[]; at: number }>();
  let stopping = false;
  process.on("SIGINT", () => (stopping = true));
  process.on("SIGTERM", () => (stopping = true));
  while (!stopping) {
    const started = Date.now();
    try {
      if (Date.now() - cfgAt > 10 * 60_000) {
        cfg = await readConfig(data.registry, data.registryRpcs);
        cfgAt = Date.now();
      }
      await tick(data, cfg, postsCache);
      saveData(data);
    } catch (err) {
      console.warn("tick échoué :", String(err).split("\n")[0].slice(0, 200));
    }
    const wait = TICK_MS - (Date.now() - started);
    if (wait > 0 && !stopping) await new Promise((r) => setTimeout(r, wait));
  }
  saveData(data);
  console.log("Relais arrêté.");
}

async function status() {
  const data = loadData();
  const devices = Object.values(data.subs);
  console.log(`Relais n°${data.relayId ?? "—"} (${data.network}) · contrat ${data.pushContract ?? "—"}`);
  console.log(`Clé de chiffrement : ${encPublic(data)}`);
  console.log(`Clé VAPID          : ${vapidHex(data.vapidPublic)}`);
  console.log(`${new Set(devices.map((d) => lc(d.a))).size} compte(s), ${devices.length} appareil(s) abonné(s)`);
}

const commands: Record<string, () => Promise<void>> = { init, register, run, status };
if (!commands[command]) throw new Error(`Commande inconnue « ${command} » : init | register | run | status`);
await commands[command]();
