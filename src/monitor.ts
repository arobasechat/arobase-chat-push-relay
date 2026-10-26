import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parseArgs } from "node:util";
import { createPublicClient, formatEther, hexToString, http, parseEther, type Address } from "viem";
import { registryAbi } from "./abi.ts";
import { DATA_DIR, registryLocation } from "./paths.ts";

const { values: flags } = parseArgs({
  options: {
    network: { type: "string", default: "mainnet" },
    watch: { type: "boolean", default: false },
    interval: { type: "string", default: "600" },
    "min-deposit": { type: "string", default: "0.5" },
  },
});

const webhook = process.env.MONITOR_WEBHOOK;
const minDeposit = parseEther(flags["min-deposit"]!);
const minDeposits = Object.fromEntries(
  (process.env.MONITOR_MIN_DEPOSITS ?? "")
    .split(",")
    .map((x) => x.trim().split(":"))
    .filter(([id, v]) => id && v)
    .map(([id, v]) => [id, parseEther(v)]),
) as Record<string, bigint>;

const epAbi = [{ type: "function", name: "balanceOf", inputs: [{ type: "address" }], outputs: [{ type: "uint256" }], stateMutability: "view" }] as const;
const pmAbi = [
  { type: "function", name: "remainingToday", inputs: [], outputs: [{ type: "uint256" }], stateMutability: "view" },
  { type: "function", name: "dailyBudget", inputs: [], outputs: [{ type: "uint256" }], stateMutability: "view" },
] as const;

const location = () => registryLocation(flags.network!);

type Check = { key: string; ok: boolean; text: string };

async function firstWorking(rpcs: string[]) {
  const results = await Promise.all(
    rpcs.map(async (u) => {
      try {
        const c = createPublicClient({ transport: http(u, { timeout: 8_000, retryCount: 0 }) });
        await c.getBlockNumber();
        return u;
      } catch {
        return undefined;
      }
    }),
  );
  return { working: results.filter(Boolean) as string[], total: rpcs.length };
}

async function runChecks(): Promise<Check[]> {
  const { registry, rpcs } = location();
  const checks: Check[] = [];
  const reg = await firstWorking(rpcs);
  if (!reg.working.length) return [{ key: "registry", ok: false, text: `Aucun RPC de la chain du Registry ne répond (${reg.total} testés)` }];
  const client = createPublicClient({ transport: http(reg.working[0], { timeout: 20_000 }) });
  const [version, , , chains, keys, values] = await client.readContract({ address: registry, abi: registryAbi, functionName: "snapshot" });
  checks.push({ key: "registry", ok: true, text: `Registry v${version}` });
  const params: Record<string, unknown> = {};
  keys.forEach((k, i) => {
    try {
      params[hexToString(k, { size: 32 }).replace(/\0+$/, "")] = JSON.parse(hexToString(values[i]));
    } catch {
      return;
    }
  });

  const urls = new Map<number, { name: string; rpcs: string[] }>();
  for (const c of chains) if (c.active) urls.set(Number(c.chainId), { name: c.name, rpcs: [...new Set([...(urls.get(Number(c.chainId))?.rpcs ?? []), ...c.rpcs])] });
  const working = new Map<number, string[]>();
  for (const [id, c] of urls) {
    const r = await firstWorking(c.rpcs);
    working.set(id, r.working);
    const ok = r.working.length >= Math.min(2, r.total);
    checks.push({ key: `rpc:${id}`, ok, text: `${c.name} : ${r.working.length}/${r.total} RPC répondent` });
  }

  const aa = (params.aa ?? {}) as Record<string, { entryPoint: Address; paymaster: Address; bundlers: string[] }>;
  for (const [id, cfg] of Object.entries(aa)) {
    const rpc = working.get(Number(id))?.[0];
    const name = urls.get(Number(id))?.name ?? id;
    if (!rpc) continue;
    const c = createPublicClient({ transport: http(rpc, { timeout: 20_000 }) });
    const deposit = await c.readContract({ address: cfg.entryPoint, abi: epAbi, functionName: "balanceOf", args: [cfg.paymaster] });
    const floor = minDeposits[id] ?? minDeposit;
    checks.push({
      key: `deposit:${id}`,
      ok: deposit >= floor,
      text: `Paymaster ${name} : dépôt ${Number(formatEther(deposit)).toFixed(4)}${deposit < floor ? ` (sous le seuil de ${formatEther(floor)}, rechargez avec « pnpm fund-paymaster ${id} <montant> »)` : ""}`,
    });
    const [budget, remaining] = await Promise.all([
      c.readContract({ address: cfg.paymaster, abi: pmAbi, functionName: "dailyBudget" }).catch(() => 0n),
      c.readContract({ address: cfg.paymaster, abi: pmAbi, functionName: "remainingToday" }).catch(() => undefined),
    ]);
    if (budget > 0n && remaining !== undefined) {
      const low = remaining * 10n < budget;
      checks.push({ key: `budget:${id}`, ok: !low, text: `Paymaster ${name} : ${formatEther(remaining)} restant sur ${formatEther(budget)} aujourd'hui${low ? " (budget presque épuisé, possible spam)" : ""}` });
    }
    let alive = 0;
    for (const b of cfg.bundlers) {
      try {
        const res = await fetch(b, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_supportedEntryPoints", params: [] }),
          signal: AbortSignal.timeout(8_000),
        });
        if (res.ok && JSON.stringify(await res.json()).toLowerCase().includes(cfg.entryPoint.slice(2).toLowerCase())) alive++;
      } catch {
        continue;
      }
    }
    checks.push({ key: `bundlers:${id}`, ok: alive > 0, text: `Bundlers ${name} : ${alive}/${cfg.bundlers.length} répondent` });
  }

  for (const entry of (process.env.MONITOR_BALANCES ?? "").split(",").map((x) => x.trim()).filter(Boolean)) {
    const [id, address, min = "0.1", label = "executor"] = entry.split(":");
    const rpc = working.get(Number(id))?.[0];
    if (!rpc || !address) continue;
    const balance = await createPublicClient({ transport: http(rpc, { timeout: 20_000 }) })
      .getBalance({ address: address as Address })
      .catch(() => undefined);
    if (balance === undefined) continue;
    const ok = balance >= parseEther(min);
    checks.push({
      key: `balance:${id}:${address.toLowerCase()}`,
      ok,
      text: `${label} ${urls.get(Number(id))?.name ?? id} (${address.slice(0, 8)}…) : ${Number(formatEther(balance)).toFixed(4)}${ok ? "" : ` (sous ${min}, rechargez-le)`}`,
    });
  }

  const relayFile = resolve(DATA_DIR, `${flags.network}.json`);
  if (existsSync(relayFile)) {
    const { mtimeMs } = await import("node:fs").then((fs) => fs.statSync(relayFile));
    const age = (Date.now() - mtimeMs) / 1000;
    checks.push({ key: "relay", ok: age < 300, text: `Relais push : dernière activité il y a ${Math.round(age)} s${age >= 300 ? " (arrêté ?)" : ""}` });
  }
  return checks;
}

const redactUrls = (text: string) =>
  text.replace(/\b(https?|wss?):\/\/([^\s/?#"'<>]+)[^\s"'<>]*/gi, (_, scheme: string, host: string) => `${scheme}://${host.replace(/^[^@]*@/, "")}`);

async function alert(raw: string) {
  if (!webhook) return;
  const text = redactUrls(raw);
  const body = webhook.includes("ntfy")
    ? text
    : JSON.stringify(webhook.includes("discord") ? { content: text } : { text });
  await fetch(webhook, {
    method: "POST",
    headers: webhook.includes("ntfy") ? { Title: "arobase.chat monitor" } : { "content-type": "application/json" },
    body,
  }).catch((e) => console.warn("webhook en échec :", String(e)));
}

const previous = new Map<string, boolean>();
async function once() {
  let checks: Check[];
  try {
    checks = await runChecks();
  } catch (err) {
    checks = [{ key: "monitor", ok: false, text: `Monitor en échec : ${String(err).split("\n")[0].slice(0, 200)}` }];
  }
  console.log(`\n${new Date().toISOString()}`);
  for (const c of checks) console.log(`${c.ok ? "✓" : "✗"} ${c.text}`);
  const changed = checks.filter((c) => previous.get(c.key) !== c.ok && (previous.has(c.key) || !c.ok));
  for (const c of checks) previous.set(c.key, c.ok);
  if (changed.length) await alert(changed.map((c) => `${c.ok ? "✅ rétabli" : "⚠️"} ${c.text}`).join("\n"));
  return checks.every((c) => c.ok);
}

if (flags.watch) {
  for (;;) {
    await once();
    await new Promise((r) => setTimeout(r, Number(flags.interval) * 1000));
  }
} else process.exit((await once()) ? 0 : 1);
