import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Address } from "viem";
import { withLocalRpcs } from "./rpcs.ts";

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const DATA_DIR = resolve(process.env.RELAY_DATA_DIR ?? resolve(ROOT, "data"));

export function registryLocation(network: string): { registry: Address; rpcs: string[] } {
  if (process.env.REGISTRY && process.env.REGISTRY_RPC) {
    return { registry: process.env.REGISTRY as Address, rpcs: process.env.REGISTRY_RPC.split(",").map((s) => s.trim()) };
  }
  const file = resolve(ROOT, "config", `${network}.json`);
  if (!existsSync(file)) {
    throw new Error(`Registry inconnu : définissez REGISTRY et REGISTRY_RPC, ou créez config/${network}.json (voir config/example.json).`);
  }
  const cfg = JSON.parse(readFileSync(file, "utf8")) as { registry: Address; chainId: number; rpcs: string[] };
  return { registry: cfg.registry, rpcs: withLocalRpcs(cfg.chainId, cfg.rpcs) };
}
