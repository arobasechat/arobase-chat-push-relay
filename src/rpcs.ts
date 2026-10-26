import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const file = resolve(dirname(fileURLToPath(import.meta.url)), "..", "rpcs.local.json");
const local: Record<string, string[]> = existsSync(file) && statSync(file).isFile() ? JSON.parse(readFileSync(file, "utf8")) : {};

export function withLocalRpcs(chainId: number | string, rpcs: string[] = []) {
  const own = local[String(chainId)] ?? [];
  return [...own, ...rpcs.filter((u) => !own.includes(u))];
}
