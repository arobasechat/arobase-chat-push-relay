# arobase.chat — push relay

A decentralized Web Push relay for [arobase.chat](https://arobase.chat), plus a monitoring tool for an instance.

Anyone can run a relay: there is no central notification server. Relays publish their public keys in the onchain `PushRelays` registry, and users pick one in the app. The relay only learns what it needs to notify you, and that information stays encrypted for the relay.

## How it works

1. **Registration.** `relay register` publishes the relay's X25519 encryption key and VAPID public key in `PushRelays` (see [arobase-chat-evm-contracts](https://github.com/arobasechat/arobase-chat-evm-contracts)).
2. **Subscription.** The app encrypts the browser's push subscription for the relay's key. The subscription is signed with the user's identity (EIP-712 `Push`), then sent to `PushRelays.subscribe` from a throwaway, gas-sponsored address. Only this relay can read it.
3. **Watching.** `relay run` watches the chains listed in the `Registry`:
   - mentions, replies, notes, reposts and quotes (`Content.Notify`);
   - follows and likes (`Social.Acted`);
   - messages in your conversations (`Inbox`), when the user opted in;
   - posts of the platform account.
4. **Delivery.** It sends end-to-end encrypted Web Push notifications. Direct messages stay encrypted: the relay only knows that a message arrived.

**Direct messages.** A subscription carries up to 200 *tag keys* (16 bytes each), one per conversation key, derived from it with HKDF. The relay recomputes the tags that rotate every 4,096 blocks (`sha256(tagKey ‖ bucket)`) and watches `Encrypted` events with those tags. It never learns conversation ids, members or contents, and it is not told about invites, which only the recipient can detect.

**Input validation.** A subscription is dropped unless every field is well formed: 16-byte device id, finite expiry in the future, push endpoint on a known push service, base64url keys of bounded size, at most 200 tag keys. A malformed record cannot reach `eth_getLogs` filters or stall a scan. Expired subscriptions are dropped automatically.

The relay exposes no port: it reads RPCs and writes to browser push services.

### Relays are not trusted

Every notification carries an **onchain proof**: chain id, transaction hash and log index of the event that triggered it (`p: { c, tx, i }`). Before displaying anything, the app's service worker:
1. fetches the receipt from an RPC of the instance;
2. checks that the log is the expected event, from the expected contract, addressed to this user, by the claimed author;
3. shows only fixed texts built from validated fields, plus announcement text read from the chain itself and only for the platform account.

A notification that fails verification becomes a generic "New activity" one, and floods are collapsed past 20 per hour. A malicious or compromised relay therefore cannot invent notifications, inject text or links, or spam.

The instance lists its **verified relays** in the `push.relays` parameter of the Registry (`pnpm propose set-push-relays <id…>` in arobase-chat-evm-contracts). The app offers verified relays by default and shows the others behind a warning.

## Requirements

- Node.js 22+ and pnpm 10+, or Docker
- The `Registry` address of the instance and RPCs for its chain
- A few cents of the social chain's gas token (xDAI on Gnosis) on the operator address, for `register` only

## Usage

```bash
pnpm install
cp config/example.json config/mainnet.json   # set the Registry address and RPCs
# or: export REGISTRY=0x… REGISTRY_RPC=https://rpc1,https://rpc2

pnpm relay init --network mainnet --contact mailto:you@example.org
RELAY_PK=0x… pnpm relay register --network mainnet --name "My relay" --info "https://example.org"
pnpm relay run --network mainnet
pnpm relay status --network mainnet
```

- `init` creates `data/<network>.json` (mode 600). This file holds the relay's encryption and VAPID keys, plus its subscription state. **Back it up and never share it**: if you lose it, every subscription to your relay becomes unreadable.
- `register` takes the operator key from the `RELAY_PK` environment variable, never as an argument. Running it again updates the existing relay.
- Environment variables:
  - `RELAY_DATA_DIR`: data folder (default `./data`);
  - `RELAY_TICK_MS`: polling interval;
  - `RELAY_MAX_SPAN`: maximum block span per `getLogs`;
  - `RELAY_ALLOW_HTTP=1`: allow `http://` and arbitrary push endpoints, for local tests only;
  - `RELAY_EXTRA_PUSH_HOSTS`: comma-separated extra push service hostnames.
- **Push endpoints are allow-listed** (`fcm.googleapis.com`, `updates.push.services.mozilla.com`, `*.push.apple.com`, `*.notify.windows.com`), and redirects are not followed. Without this, anyone could subscribe with an internal URL and make the relay send requests inside its own network (SSRF).

### Private RPCs

To use your own nodes without publishing them, create `rpcs.local.json` (ignored by git):

```json
{ "100": ["https://my-private-gnosis-node"], "5042": ["https://my-private-arc-node"] }
```

They are tried before the public RPCs.

## Monitoring

```bash
MONITOR_WEBHOOK=https://ntfy.sh/my-topic pnpm monitor --network mainnet --watch --interval 600
```

It checks:
- the RPCs of every chain;
- the deposit and daily budget of each paymaster;
- the bundlers;
- the relay's last activity;
- optionally, the balances of chosen addresses.

Alerts go to `MONITOR_WEBHOOK` when a check changes state. ntfy, Discord and Slack are detected automatically; any other URL receives a JSON `{ "text": … }` POST. Without `--watch`, the exit code is 1 when a check fails, so it can run from cron.

| Variable | Example | Meaning |
|---|---|---|
| `MONITOR_MIN_DEPOSITS` | `100:0.5,5042:1,8453:0.003` | Minimum paymaster deposit per chain (default `--min-deposit 0.5`) |
| `MONITOR_BALANCES` | `100:0xabc…:0.3:executor` | `chainId:address:minimum:label` entries, comma-separated (for example, bundler executors) |

## Docker

```bash
docker build -t arobase-chat-push-relay .
docker run -d --name relay -v "$PWD/data:/app/data" -e REGISTRY=0x… -e REGISTRY_RPC=https://… arobase-chat-push-relay
```

[arobase-chat-bundler-config](https://github.com/arobasechat/arobase-chat-bundler-config) runs the relay and the monitor next to the ERC-4337 bundlers, using this repository as its build context.

## Tests

```bash
pnpm test        # node:test, no network needed
pnpm typecheck
```

The relay logic lives in `src/core.ts`; RPC clients, the push sender and the clock are injected, so it runs entirely against fakes. `src/relay.ts` is only the CLI around it. The tests cover:
- **subscriptions**: EIP-712 signatures, both direct and through a session key; rejection of forged, tampered, expired or malformed records; the `https` endpoint rule; lifetime cap;
- **sealed payloads**: decryption with the current or a rotated key; ciphertexts meant for another relay are ignored;
- **device management**: add, update, unsubscribe, 10-device limit, expiry;
- **block scanning**: first run starts at the head, ranges are covered exactly once, the span shrinks when the RPC refuses a range, and the cursor never moves on failure;
- **event detection**: mentions, replies, notes, reposts, quotes, follows (no unfollows or self-follows), likes on recent posts, platform announcements and direct messages; one failing RPC does not block the others;
- **delivery**: grouping, urgency, payload contents, every device of a recipient, removal of subscriptions gone from the push service (404/410), and transient failures kept.

## ABI

`src/abi.ts` is generated by `pnpm gen-abi` in `arobase-chat-evm-contracts`. Do not edit it by hand.

## License

[Apache-2.0](LICENSE). Redistributions must keep the [NOTICE](NOTICE) file; please credit "arobase.chat" if you host a fork.
