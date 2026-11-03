# VaultNode Protocol Specification

**Status:** v1.0 — single source of truth. The firmware (`firmware/`) and the
attack testbench (`attack-testbench/`) MUST both conform to this document. If code
and this document disagree, the code is wrong.

The key words MUST, MUST NOT, SHOULD, and MAY are used as in RFC 2119.

---

## 0. Conventions

| Item | Rule |
|---|---|
| Byte order | All multi-byte integers inside cryptographic inputs are **big-endian**. |
| Hex | Emitted as **lowercase**. Parsers MUST accept only `[0-9a-fA-F]` and MUST reject odd lengths or wrong lengths. Cryptographic operations always use the **decoded raw bytes**, never the hex text. |
| `\|\|` | Byte concatenation. ASCII literals such as `"enc"` are their raw ASCII bytes with no terminator. |
| Time | `ts` = Unix epoch in **milliseconds** (`uint64`). The firmware uses `system_clock` for `ts` comparisons and `steady_clock` for durations (`verify_us`, timeouts). |
| JSON | UTF-8. One object per message. Unknown fields MUST be ignored; missing or wrongly typed required fields cause rejection. |
| Constant time | Every comparison of a MAC, signature, or proof MUST use a constant-time comparison (`CRYPTO_memcmp` in C++, `hmac.compare_digest` in Python). |

### 0.1 Identifiers

| Name | Format | Size |
|---|---|---|
| `uid` | 8 hex chars | 4 bytes (MIFARE-style UID) |
| `nonce` (fw_nonce) | 32 hex chars | 16 bytes, from a CSPRNG (`RAND_bytes`) |
| `badge_nonce` | — (never sent in clear) | 16 bytes, from the badge's CSPRNG |
| `iv` | 32 hex chars | 16 bytes, fresh random per response |
| `mac`, `proof`, `sig` | 64 hex chars | 32 bytes (HMAC-SHA256 output) |

---

## 1. Keys and configuration

All keys are 32 bytes, supplied as 64 hex chars via environment variables.

| Env var | Required | Purpose |
|---|---|---|
| `VAULTNODE_ID` | yes | Node identifier used in MQTT topics. MUST match `[a-z0-9-]{1,32}`. |
| `MASTER_KEY_HEX` | yes | Root key for per-badge key diversification (§2.1). |
| `COMMAND_KEY_HEX` | yes | Verifies controller → firmware commands (§3.3). |
| `TELEMETRY_KEY_HEX` | yes | Signs firmware → controller telemetry (§3.2). |
| `MQTT_HOST` | yes | Broker hostname (e.g. `mosquitto`). |
| `MQTT_PORT` | no | Default `1883`. |
| `VAULTNODE_STATE_PATH` | no | Persistent state file (§5.4). Default `/var/lib/vaultnode/vaultnode_state.json`. |

**Startup validation.** The firmware MUST refuse to start (non-zero exit, error to stderr)
if any required variable is missing, if a key is not exactly 64 valid hex chars, if a key is all-zero,
or if any two of the three keys are equal (key separation).

The firmware MUST NOT log key material, and MUST call `OPENSSL_cleanse` on key buffers on shutdown.

> **Dev only.** `.env.example` contains public, obviously fake keys (their ASCII decodes to
> `DEV-ONLY-…-DO-NOT-USE`). Real deployments keep `MASTER_KEY` in a secure element / TPM
> and never expose it to application memory; diversification (§2.1) happens inside the SE.

---

## 2. Reader channel (virtual serial RFID reader)

**Transport:** TCP port **5555**, newline-delimited JSON (`\n`-terminated, one object per line).

**Framing limits:** The maximum line length is **1024 bytes**, including the newline. Longer
lines, invalid UTF-8, or invalid JSON MUST cause the firmware to close the connection without
replying. One authentication exchange may be outstanding per connection. The firmware MUST
close a connection that sends no complete line within **10 s**.

### 2.1 Per-badge key diversification

```
K_enc = HMAC-SHA256(MASTER_KEY, "enc" || uid)[0:16]    // AES-128 key
K_mac = HMAC-SHA256(MASTER_KEY, "mac" || uid)          // 32-byte HMAC key
```

`uid` here is the 4 raw bytes. A cloned UID is useless without that badge's derived keys,
and compromising one badge's keys reveals nothing about another badge's keys or `MASTER_KEY`.

### 2.2 Message flow

```
Badge                                         Firmware
  | --- hello {uid} --------------------------> |
  | <-- challenge {nonce, ts, seq} ------------ |   fw_nonce stored as outstanding, expires in 5 s
  | --- response {uid, iv, ct, mac} ----------> |   verify (§2.4)
  | <-- result {granted, proof?, reason, ...} - |
```

**1. hello (Badge → FW)**
```json
{"type":"hello","uid":"04a1b2c3"}
```

**2. challenge (FW → Badge)**
```json
{"type":"challenge","nonce":"000102030405060708090a0b0c0d0e0f","ts":1767225600000,"seq":42}
```
- `nonce`: 16 fresh CSPRNG bytes (`fw_nonce`).
- `ts`: firmware time at issue (informational; the badge uses its own clock in the response).
- `seq`: global `uint64` challenge counter. It increments by 1 per challenge and is never reused within a process lifetime.
- The firmware MUST issue a challenge for every syntactically valid `hello`, **including while
  `LOCKED_OUT`** and for revoked UIDs. Denial is decided only at the result, so `hello`
  cannot be used to probe state.
- A new `hello` on a connection that already has an outstanding challenge invalidates (consumes) the old one.

**3. response (Badge → FW)**
```json
{"type":"response","uid":"04a1b2c3","iv":"a0a1…af","ct":"<96 hex>","mac":"<64 hex>"}
```
```
plaintext = fw_nonce(16) || badge_nonce(16) || ts_ms(8, BE)          // 40 bytes
ct        = AES-128-CBC(K_enc, iv, PKCS7(plaintext))                  // exactly 48 bytes
mac       = HMAC-SHA256(K_mac, uid(4) || fw_nonce(16) || iv(16) || ct(48))   // encrypt-then-MAC
```
- `ct` MUST be exactly 96 hex chars (48 bytes); other lengths are rejected before any crypto.
- `uid` MUST equal the `uid` from this connection's `hello`.
- The MAC input is unambiguous because every field has a fixed length and `ct` comes last.

**4. result (FW → Badge)**

Success:
```json
{"type":"result","granted":true,"proof":"<64 hex>","reason":"granted","verify_us":183}
```
```
proof = HMAC-SHA256(K_mac, "fw" || badge_nonce)
```
The badge MUST verify `proof` in constant time. A wrong or missing proof means the reader is
not genuine (mutual authentication).

Failure (**uniform**, whatever the cause):
```json
{"type":"result","granted":false,"reason":"denied"}
```
- On failure there is **no `proof` and no `verify_us`**. `verify_us` would act as a timing
  oracle that separates "MAC failed" (fast) from "MAC ok, nonce stale" (slower).
- The true cause is recorded only in the internal log and in the signed `auth` telemetry event
  (§3.2), using the internal reason codes in §2.5.

`verify_us` is the firmware-side duration, measured on `steady_clock`, from the moment the
complete `response` line has been parsed to the moment the grant decision is made. It does not include
network I/O or JSON serialization of the result.

### 2.3 Challenge lifecycle

- **Lifetime:** A challenge expires **5000 ms** (steady_clock) after it is issued.
- **Single use:** A challenge is consumed by the first `response` that references it on its
  connection, **whether verification succeeds or fails**. Any further response gets
  `denied` (`nonce_unknown`).
- **Seen-nonce ring buffer:** The firmware keeps the last **256** consumed `fw_nonce` values in a
  fixed-size ring buffer. Before issuing a nonce, the firmware MUST regenerate it if the value appears in the ring
  (this guards against RNG failure). During verification, the firmware MUST deny any decrypted `fw_nonce` found in the ring
  (`nonce_replay`).
- The firmware closes a connection when the 5 s challenge timer expires without a `response`.

### 2.4 Verification order (normative)

The firmware MUST perform these steps in exactly this order and stop at the first failure:

| # | Check | Internal reason on failure |
|---|---|---|
| 0 | JSON well-formed, `type=="response"`, all fields present with correct hex lengths, `uid` matches `hello` | `malformed` |
| 1 | An outstanding, unexpired challenge exists on this connection | `nonce_unknown` / `nonce_expired` |
| 2 | Derive `K_enc`, `K_mac` from `uid`; **constant-time MAC check FIRST** over `uid‖fw_nonce_outstanding‖iv‖ct` | `bad_mac` |
| 3 | AES-128-CBC decrypt + PKCS7 unpad. Plaintext MUST be exactly 40 bytes | `decrypt_fail` |
| 4 | Decrypted `fw_nonce` == outstanding challenge nonce (constant-time) and not in the seen ring | `nonce_mismatch` / `nonce_replay` |
| 5 | `abs(ts_ms − now_ms) ≤ 5000` | `stale_ts` |
| 6 | `uid` not in the revocation list (§5.3) | `revoked` |
| 7 | Node state is not `LOCKED_OUT` | `locked_out` |

The outstanding challenge is consumed (moved into the seen ring) at step 1 for any request that
reaches step 1, so a failed attempt cannot be retried against the same nonce. Because the MAC is
checked before decryption, a padding oracle cannot exist: unauthenticated ciphertext is never
decrypted.

Every attempt that reaches step 1 emits exactly one `auth` telemetry event (§3.2).

### 2.5 Internal reason codes

`granted`, `malformed`, `nonce_unknown`, `nonce_expired`, `bad_mac`, `decrypt_fail`,
`nonce_mismatch`, `nonce_replay`, `stale_ts`, `revoked`, `locked_out`.
These appear **only** in logs and signed telemetry, never on the reader channel.

---

## 3. MQTT

**Broker:** Mosquitto, port **1883**. QoS 1 for `cmd` and for alert telemetry (`tamper`, `thermal`,
`lockdown`). QoS 0 for `heartbeat`. Retain is false everywhere.

> Dev note: the compose broker is a plaintext listener on the internal Docker network.
> Message integrity comes from the application-layer HMACs below, not from the transport. Production
> adds TLS (8883), per-client credentials, and topic ACLs.

### 3.1 Topics

| Topic | Direction | Payload |
|---|---|---|
| `vaultnode/<node_id>/telemetry` | FW → controller | signed telemetry (§3.2) |
| `vaultnode/<node_id>/cmd` | controller → FW | signed command (§3.3) |

### 3.2 Telemetry (FW publishes)

```json
{"event":"thermal","data":{...},"seq":7,"ts":1767225600000,"sig":"<64 hex>"}
```

**Canonical signing string**
```
event|node_id|seq|ts|data_json
sig = HMAC-SHA256(TELEMETRY_KEY, utf8(canonical))
```
- `seq` and `ts` are rendered as base-10 integers with no leading zeros or sign.
- `data_json` is compact JSON with **keys sorted** (byte order) and no whitespace. In Python this is
  `json.dumps(data, separators=(",",":"), sort_keys=True)`.
- **To avoid float canonicalization mismatches between C++ and Python, `data` values are limited to
  integers, booleans, and ASCII strings matching `[A-Za-z0-9_.:-]*`.** No floats, nulls, or nested objects.
  Physical quantities use fixed-point integers: `temp_cx100` (°C × 100) and `humidity_px100` (%RH × 100).
- Telemetry `seq` increases strictly, is persisted (§5.4), and continues across restarts.

**Events and `data` fields**

| `event` | When | `data` |
|---|---|---|
| `auth` | each verification attempt that reaches step 1 | `uid`, `granted` (bool), `reason` (§2.5), `verify_us` (int) |
| `tamper` | tamper GPIO 17 rises | `pin` (17), `state` (`LOCKED_OUT`) |
| `thermal` | temperature or humidity breach | `cause` (`thermal`/`humidity`), `temp_cx100`, `humidity_px100`, `state` |
| `lockdown` | entering LOCKED_OUT via remote `lockdown` cmd, **or** leaving it via `unlock` | `cause` (`remote`/`unlock`), `state` |
| `revoke_ack` | successful `revoke` | `uid`, `revoked_count` |
| `heartbeat` | every **10 s** | `state`, `temp_cx100`, `humidity_px100`, `tamper` (bool), `uptime_s` |
| `cmd_rejected` | a command fails verification or precondition | `reason` (§3.3), `cmd_seq` (int, `-1` if unparsable) |

### 3.3 Commands (controller publishes)

```json
{"cmd":"revoke","uid":"04a1b2c3","seq":2,"ts":1767225601000,"sig":"<64 hex>"}
```

**Canonical signing string**
```
cmd|uid|seq|ts            (uid = "" when absent)
sig = HMAC-SHA256(COMMAND_KEY, utf8(canonical))
```

| `cmd` | `uid` | Effect |
|---|---|---|
| `lockdown` | MUST be absent/empty | → `LOCKED_OUT` (cause `remote`) |
| `unlock` | MUST be absent/empty | `LOCKED_OUT` → `NORMAL`, only if no tamper or thermal condition is still active |
| `revoke` | REQUIRED (8 hex) | add `uid` to the persisted revocation list |

**Verification order (normative)**

| # | Check | `cmd_rejected.reason` |
|---|---|---|
| 0 | Payload ≤ 1024 B, valid JSON, required fields present and well typed | `malformed` |
| 1 | Constant-time `sig` check | `bad_sig` |
| 2 | `seq` > last accepted command `seq` (strictly increasing) | `replay` |
| 3 | `abs(ts − now_ms) ≤ 30000` | `stale_ts` |
| 4 | `cmd` known and `uid` rules above satisfied | `bad_cmd` |
| 5 | Preconditions (`unlock` with an active tamper or thermal condition) | `condition_active` |

The last accepted `seq` is updated and persisted **only after steps 0–4 pass**, so forged or
malformed messages cannot burn sequence numbers. (A command rejected at step 5 still consumes its
`seq`, because it was authentic.)

---

## 4. Environment sensors and GPIO (virtual)

| Device | Virtual bus | Detail |
|---|---|---|
| Temp/humidity sensor | I²C addr **0x44** (SHT3x-style) | Polled every **500 ms**. Default reading 22.00 °C / 40.00 %RH with small random drift. |
| Tamper switch | GPIO **17**, input | 1 = enclosure open (tamper) |
| Lockout relay | GPIO **27**, output | 1 = relay engaged (lockout: door strike power cut). Fail-secure. |

**Thresholds** (a breach is strictly greater than the threshold):
- Temperature > **45.00 °C** (`temp_cx100 > 4500`)
- Humidity > **85.00 %RH** (`humidity_px100 > 8500`)

### 4.1 Control socket (test-only fault injection)

**Transport:** TCP **5556**, newline-delimited JSON, one reply line per request. **Unauthenticated
by design.** The port is exposed only on the internal compose network, never published to the host, and
compiled in only when the CMake option `VAULTNODE_SIM_CONTROL=ON` (default ON; the Docker
simulation build passes it explicitly). With it OFF, the control-socket sources are not compiled at all.

| Request | Effect |
|---|---|
| `{"op":"tamper","value":true\|false}` | drive GPIO 17 |
| `{"op":"set_temp","value_cx100":4650}` | override the sensor temperature |
| `{"op":"set_humidity","value_px100":9000}` | override the sensor humidity |
| `{"op":"clear_overrides"}` | return to the simulated drift |
| `{"op":"status"}` | read state |

Reply: `{"ok":true,"state":"NORMAL"|"LOCKED_OUT","relay":0|1,"tamper":bool,"temp_cx100":int,"humidity_px100":int}`,
or `{"ok":false,"error":"..."}`.

---

## 5. Lockout state machine

```
          tamper↑ | thermal/humidity breach | signed "lockdown"
 NORMAL ───────────────────────────────────────────────────────▶ LOCKED_OUT
   ▲                                                                 │
   └──────── signed "unlock" AND tamper=0 AND no breach ─────────────┘
```

- `LOCKED_OUT` **latches**. Clearing the condition alone does not unlock.
- While in `LOCKED_OUT`, every badge attempt is denied (`locked_out`), relay GPIO 27 = 1.
- A new trigger while already `LOCKED_OUT` still publishes its alert event but does not change state.

### 5.1 Interrupt path

- Sensor and tamper changes are delivered to a dedicated **lockout thread** through an `eventfd`
  (with a condition variable as the portable fallback).
- The lockout thread requests `SCHED_FIFO` priority **80** with `pthread_setschedparam`. If that
  fails (`EPERM`, which is typical without `CAP_SYS_NICE`), it logs one warning and continues at
  `SCHED_OTHER`. This is graceful degradation, not a failure. Compose grants `cap_add: [SYS_NICE]`
  and an `rtprio` ulimit so that the FIFO path normally works.
- The lockout thread, in this order: (1) sets relay GPIO 27 = 1, (2) sets state `LOCKED_OUT`
  (atomic), (3) enqueues the alert telemetry. The relay is driven **before** any I/O.
- **Latency target:** the time from injection on the control socket to relay = 1 is under 5 ms at p99 (measured by the benchmark scripts).

### 5.2 Grant

A granted authentication is logical only: an `auth` event with `granted:true` and a `result` to
the badge. There is no strike GPIO in v1.

### 5.3 Revocation

The revocation list is a set of UIDs, persisted in the state file. Revocation is checked at step 6 of
§2.4, after cryptographic verification, so revoked badges get the same `denied` response as any
other failure.

### 5.4 Persistent state file

Path from `VAULTNODE_STATE_PATH`. The file is JSON, written atomically (write to a temp file in the same
directory, `fsync`, then `rename`) and has mode `0600`.
```json
{"version":1,"last_cmd_seq":2,"telemetry_seq":8,"revoked":["04a1b2c3"],"locked_out":false}
```
`locked_out` is persisted, so a node that loses power while locked out comes back up locked out. The file holds no
key material. It is git-ignored (`vaultnode_state.json`).

---

## 6. Known-answer test vectors

Both implementations MUST reproduce these vectors in their unit tests. They use the dev keys
from `.env.example`.

```
MASTER_KEY_HEX    = 4445562d4f4e4c592d4d41535445522d4b45592d444f2d4e4f542d5553452121
COMMAND_KEY_HEX   = 4445562d4f4e4c592d434f4d4d414e442d4b45592d444f4e4f54555345212121
TELEMETRY_KEY_HEX = 4445562d4f4e4c592d54454c454d455452592d4b45592d444f4e4f5455534521
```

### 6.1 Badge authentication

```
uid          = 04a1b2c3
fw_nonce     = 000102030405060708090a0b0c0d0e0f
badge_nonce  = 101112131415161718191a1b1c1d1e1f
ts_ms        = 1767225600000   (0x0000019b76daa800)
iv           = a0a1a2a3a4a5a6a7a8a9aaabacadaeaf

K_enc        = a9bb273b2402972e55089c11dbbeb760
K_mac        = 293feade86e4fcd77d88e01314bb8eb56699c34918ced27453552f8e2fdf7457
plaintext    = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0000019b76daa800
padded       = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0000019b76daa8000808080808080808
ct           = a754ec49d6d64f89d354796953d0a68118c441ebc646fccd725bb4aeb1d020e796c1fc06eac7077547ea1be9ba036560
mac          = 6e7c79e918af8d5050b21db0f8641aa34b2ad88a05eb75398513b21f1f8dc39b
proof        = 9ae8cde1f9cadc59b713bf24f46a0c230184bd158c5654bce8b6c79f53e0fe94
```

### 6.2 Commands

```
canonical = unlock||1|1767225600000
sig       = e6223be3f3de847eaa313eea8f903cbd55edeba728ad167afc3725124a06f5c5

canonical = revoke|04a1b2c3|2|1767225601000
sig       = faf6ce6bea1bb8bafa3e7e00b2222e0f75206ea0942835f981482f1a3d70393e
```

### 6.3 Telemetry

```
node_id   = vn-01
data      = {"temp_cx100":4650,"humidity_px100":4000,"cause":"thermal","state":"LOCKED_OUT"}
canonical = thermal|vn-01|7|1767225600000|{"cause":"thermal","humidity_px100":4000,"state":"LOCKED_OUT","temp_cx100":4650}
sig       = e2f7f5867c29f6241504aaef9da87be4c7f5f486cc6438f9f817af0e2f5003b6
```

---

## 7. Ports summary

| Port | Service | Exposure |
|---|---|---|
| 5555 | Reader channel (§2) | compose network (MAY be published for demos) |
| 5556 | Control / fault injection (§4.1) | compose network **only** |
| 1883 | Mosquitto (§3) | compose network |
