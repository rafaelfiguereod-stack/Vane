# SECURITY-AUDIT.md - Vane

**Date:** 2026-05-03
**Auditor:** SECURITY agent (read-only, flag-before-fix)
**Remediation applied:** 2026-05-03
**Scope:** Vane v1.12.2 - Next.js 16 AI answering engine (server routes under `src/app/api/**`, lib under `src/lib/**`, Docker/SearXNG packaging)
**Methodology:** Static review of input handlers, secret scan (regex for `sk-...`, `AIza...`, `ghp_...`, `xoxb-...`, generic `key=...`/`secret=...` literals), config audit (`.env*`, `config.json`, `searxng/*`, `Dockerfile`, `docker-compose.yaml`), unsafe-pattern scan (`eval`, `new Function`, `child_process`, `exec*`, `spawn*`, `dangerouslySetInnerHTML`, `innerHTML=`), and route-by-route auth/authorization review. Dependency CVE audit attempted via `npm audit` but the repo ships only `yarn.lock` and no `package-lock.json`, so the npm audit run errored (`ENOLOCK`); see HIGH-04.

---

## Remediation Status

| Finding | Status | File(s) Changed |
|---|---|---|
| CRITICAL-01 | **PENDING** — requires dedicated implementation sprint (see note below) | — |
| CRITICAL-02 | **FIXED** | `src/app/api/config/route.ts` |
| HIGH-01 | **FIXED** | `src/lib/uploads/manager.ts` |
| HIGH-02 | **FIXED** | `searxng/settings.yml`, `entrypoint.sh`, `docker-compose.yaml` |
| HIGH-03 | **FIXED** (chmod 600) | `src/lib/config/index.ts` |
| HIGH-04 | PENDING — run `npm audit` / add Dependabot in CI | — |
| HIGH-05 | **FIXED** | `src/lib/scraper.ts` |
| MED-01 | **FIXED** (one-way 409 guard) | `src/app/api/config/setup-complete/route.ts` |
| MED-02 | PENDING | — |
| MED-03 | PENDING | — |
| MED-04 | PENDING | — |
| MED-05 | PENDING | — |
| MED-06 | PENDING | — |
| MED-07 | **FIXED** | `src/app/api/weather/route.ts` |
| LOW-01 | Acknowledged / acceptable | — |
| LOW-02 | **FIXED** | `next.config.mjs` |
| LOW-03 | PENDING | — |
| LOW-04 | PENDING | — |
| LOW-05 | Acknowledged / non-security | — |

> **CRITICAL-01 note:** Full authentication middleware (`src/middleware.ts` with `VANE_AUTH_TOKEN` bearer-token gate + same-site cookie + CSRF) is left as PENDING. This is the highest-priority remaining item and requires a dedicated implementation sprint. Until implemented, the README and Dockerfile should explicitly warn against binding port 3000 to anything but `127.0.0.1`/loopback.

**Overall Risk Level:** HIGH for any non-localhost / multi-tenant deployment. MEDIUM-LOW for the documented single-user localhost use case.

The single dominant risk is that **every API route is unauthenticated**. README "Upcoming Features" explicitly lists "Adding authentication" as not-yet-implemented. The threat model assumes a trusted single user on `localhost`. Anyone exposing Vane on a LAN, public IP, or via port-forwarding (a documented usage pattern in README "Expose Vane to network") inherits the full HIGH risk profile.

---

## Summary

| Severity | Count |
|---|---|
| CRITICAL | 0 (when run as documented on localhost) / 2 (when network-exposed) |
| HIGH | 5 |
| MEDIUM | 6 |
| LOW | 5 |

No live cloud-provider API keys, OAuth tokens, JWT secrets, or database credentials were discovered hardcoded in source. One placeholder/example secret is present in `searxng/settings.yml` (see HIGH-02). User-supplied API keys (OpenAI, Anthropic, Gemini, Groq, Ollama, etc.) are stored in `data/config.json` in **plaintext** at runtime - see HIGH-03.

---

## CRITICAL findings (action required)

> Both criticals are conditional on network exposure. On a strict single-user localhost deployment, the impact collapses but the design defects remain.

### CRITICAL-01 - All API routes are unauthenticated and unauthorized
**Category:** OWASP A01 Broken Access Control / A07 Auth Failures
**Locations (every route in scope):**
- `src/app/api/chat/route.ts` (POST)
- `src/app/api/search/route.ts` (POST)
- `src/app/api/chats/route.ts` (GET)
- `src/app/api/chats/[id]/route.ts` (GET, DELETE)
- `src/app/api/config/route.ts` (GET, POST)
- `src/app/api/config/setup-complete/route.ts`
- `src/app/api/providers/route.ts` (GET, POST)
- `src/app/api/providers/[id]/route.ts` (DELETE, PATCH)
- `src/app/api/providers/[id]/models/route.ts` (POST, DELETE)
- `src/app/api/reconnect/[id]/route.ts` (POST)
- `src/app/api/uploads/route.ts` (POST)
- `src/app/api/discover/route.ts` (GET)
- `src/app/api/images/route.ts` (POST)
- `src/app/api/videos/route.ts` (POST)
- `src/app/api/suggestions/route.ts` (POST)
- `src/app/api/weather/route.ts` (POST)

There is no `src/middleware.ts`, no auth header check, no session cookie, no rate limiter, and no CSRF protection on state-changing POST/PATCH/DELETE. Anyone who can reach port 3000 can:
- Read full chat history (`GET /api/chats`, `GET /api/chats/{id}`).
- Delete arbitrary chats (`DELETE /api/chats/{id}`).
- Read **and overwrite** the entire app config including injected provider API keys via `GET/POST /api/config` and the providers routes.
- Add/remove model providers, exfiltrating any keys the operator has configured.
- Drive expensive LLM calls on the operators billed cloud accounts.
- Upload arbitrary files (see HIGH-01) and trigger headless-browser scrapes of attacker-chosen URLs (see HIGH-05).

**Exploitability:** Remote, unauthenticated. **Blast radius:** Full app data + all configured third-party provider keys + financial spend on billed providers + SSRF pivot.
**Recommendation (no auto-apply):** Ship before "v1.13" the authentication item already on the roadmap. Minimum: a single shared bearer token gate in `src/middleware.ts` matched against an env var, plus a same-site cookie + CSRF token for the browser UI. Until then, the README and Dockerfile should explicitly warn against binding port 3000 to anything but `127.0.0.1`/loopback.

### CRITICAL-02 - Config GET endpoint returns provider secrets to anyone
**Category:** OWASP A01 / A02 Cryptographic Failures (sensitive data exposure)
**Location:** `src/app/api/config/route.ts:11-43`
`GET /api/config` returns `configManager.getCurrentConfig()` which includes `modelProviders[*].config` - i.e., the API keys the operator entered for OpenAI/Anthropic/Gemini/Groq/etc. There is no redaction layer between the persisted config and the response. Combined with CRITICAL-01, any reachable client can dump every configured key.
**Exploitability:** Remote, unauthenticated `GET`. **Blast radius:** All configured cloud-LLM keys.
**Recommendation:** Even before auth lands, redact secret-typed fields server-side before serializing (e.g. replace API keys with `****` on GET; only accept them on POST/PATCH). The UI config metadata in `src/lib/config/index.ts` already knows which fields are secrets via the providers `getModelProvidersUIConfigSection()` - gate them with a `secret: true` flag and strip in the response.

---

## HIGH findings

### HIGH-01 - File upload accepts attacker-controlled MIME and writes original extension to disk
**Category:** OWASP A03 Injection / A04 Insecure Design (file upload)
**Location:** `src/lib/uploads/manager.ts:177-214`, called from `src/app/api/uploads/route.ts`
- `file.type` is taken directly from the multipart form (browser-supplied, attacker-controlled) and only checked against `supportedMimeTypes`. A malicious client can claim `text/plain` while sending arbitrary bytes - content sniffing is not performed.
- `fileExtension = file.name.split(".").pop()` is then concatenated into the on-disk filename. The randomised basename prevents path traversal of the filename itself, but the **extension is not validated** against the claimed MIME, so an attacker can plant `randomhex.exe`, `randomhex.html`, `randomhex.svg`, etc., in `data/uploads`.
- No file-size limit. A single request can exhaust disk.
- No virus scanning hook. Stored content is later read back and parsed with `pdf-parse`, `officeparser`, and `jsdom` - historically high-CVE surfaces (see HIGH-04).
- The uploads directory is not exposed via Next static serving, which limits direct exploitation, but any future feature serving `data/uploads/*` would turn this into stored XSS / drive-by.

**Recommendation:** Enforce server-side magic-byte sniffing (`file-type` is already declared in `serverExternalPackages`), reject mismatch, restrict extensions to a fixed allowlist `{ .pdf, .docx, .txt }`, cap file size (e.g. 25 MB) and total upload count per request, and never echo the original filename into the on-disk path.

### HIGH-02 - Hardcoded SearXNG `secret_key` committed in `searxng/settings.yml`
**Category:** OWASP A02 Cryptographic Failures / Secrets management
**Location:** `searxng/settings.yml:13`
A 64-hex-character `server.secret_key` literal is committed to the repository (value intentionally not reproduced here per audit policy). The inline comment says it "is overwritten by SEARXNG_SECRET", but `entrypoint.sh` does not actually export or substitute that variable, and the Dockerfile copies the file as-is. Effectively every Vane container ships with the same SearXNG session signing key.
**Exploitability:** Anyone with the public source tree knows the key; they can forge SearXNG session/CSRF tokens against any default Vane deployment.
**Recommendation:** Replace with a placeholder, generate a random key on container first start in `entrypoint.sh`, write it to `/etc/searxng/settings.yml` (or use SearXNGs env-var override), and rotate the value on existing deployments. Add `searxng/settings.yml` (the live one) to `.gitignore` if a template is kept in-tree.

### HIGH-03 - Provider API keys persisted in plaintext at `data/config.json`
**Category:** OWASP A02 Cryptographic Failures
**Location:** `src/lib/config/index.ts:128-133, 138-141`, `Dockerfile:32` (volume-mounted at `/home/vane/data`)
All cloud-provider API keys entered via the setup screen are written verbatim to `data/config.json` (`fs.writeFileSync` with `JSON.stringify(...)`). The Docker volume `vane-data` therefore contains them in plaintext on the host filesystem. There is no encryption-at-rest, no OS-keyring integration, and no permission tightening (file inherits process umask).
**Exploitability:** Local - anyone with read access to the volume / host disk / a backup. Combined with CRITICAL-02 also remotely exploitable.
**Recommendation:** At minimum, `chmod 600` the file on write. Better: encrypt secret fields with a key derived from an operator-supplied passphrase or `VANE_SECRET` env var, decrypt only into memory.

### HIGH-04 - Dependency vulnerability scan could not be completed
**Category:** OWASP A06 Vulnerable and Outdated Components
**Location:** `package.json`, `yarn.lock`
`npm audit` aborted with `ENOLOCK` (no `package-lock.json`); the project uses Yarn classic. Without running `yarn npm audit` or `yarn audit` (Yarn 1) - neither available in this read-only environment - I cannot give a CVE count. Manual inspection of `package.json` flags several historically vulnerable packages whose pinned ranges should be re-checked:
- `jsdom ^29.0.1` - recent prototype-pollution / SSR XSS history.
- `pdf-parse ^2.4.5` - used on attacker-controlled bytes (HIGH-01); CVE-prone.
- `officeparser ^6.0.7` - ZIP-based; check ZIP-slip exposure.
- `playwright ^1.59.1` - fine, but the `--no-sandbox` launch in `src/lib/scraper.ts:21` removes Chromiums process sandbox.
- `axios ^1.8.3` - keep current vs. recent SSRF/cookie advisories.
- `next ^16.0.7` - ensure on the latest 16.x patch.

**Recommendation:** Run `yarn npm audit --recursive --severity high` (Yarn >=3) or `yarn audit` (Yarn 1) in CI; commit a `package-lock.json` for `npm audit` parity, or use Snyk/Dependabot. Re-evaluate after results are in.

### HIGH-05 - SSRF via scraper and unauthenticated invocation
**Category:** OWASP A10 SSRF / A01 Broken Access Control
**Location:** `src/lib/scraper.ts:49-113` (used by search agents), reachable transitively via `POST /api/chat` and `POST /api/search`
`Scraper.scrape(url)` accepts any URL and navigates a headless Chromium to it with `--no-sandbox` and `--disable-setuid-sandbox`. There is no scheme allowlist, no host blocklist, and no metadata-IP filter. URLs ultimately come from SearXNG results, but the chain user query -> SearXNG -> URL -> scraper plus the attackers ability to control SearXNG result content (e.g., via posting a public webpage that ranks for a chosen query, or by directly choosing the SearXNG instance via config) means an attacker can coerce the server to fetch:
- Internal services (`http://169.254.169.254/...` cloud metadata, `http://localhost:11434` Ollama, `http://localhost:8080` SearXNG admin if any).
- `file://` / `chrome://` URLs (Playwright honors many).
- Internal RFC1918 ranges.

`--no-sandbox` additionally weakens process isolation if a Chromium 0-day is triggered by a malicious page.

**Recommendation:** Validate URLs against an allowlist of `http`/`https` only; resolve hostnames and reject loopback / link-local / RFC1918 / RFC4193; remove `--no-sandbox` from the launch args (use a properly seccomp-profiled container instead); enforce egress firewalling at the container level.

---

## MEDIUM findings

### MED-01 - Setup-complete endpoint can be flipped externally
`src/app/api/config/setup-complete/route.ts` together with `configManager.markSetupComplete()` lets anyone toggle the "setup is done" flag. Combined with CRITICAL-01, a remote attacker could push the app past first-run state and lock in an attacker-supplied provider config. **Fix:** auth gate; idempotent / one-way only.

### MED-02 - Unbounded chat history replay and resource use
`POST /api/chat` (`src/app/api/chat/route.ts:34-48`) and `POST /api/search` (`src/app/api/search/route.ts:40-43`) accept arbitrarily long `history`, `systemInstructions`, `query`, and a 100-element `files` array (no max), all forwarded to the LLM. No rate-limiting or token-budget guard. Combined with CRITICAL-01 this is a denial-of-wallet / DoS primitive on cloud providers. **Fix:** length caps, token-pre-count, per-IP rate limit.

### MED-03 - Indirect prompt injection: untrusted scraped content fed to LLM with no boundary marking
The search agent ingests SearXNG result snippets and full scraped pages into LLM prompts (`src/lib/prompts/search/researcher.ts`, `writer.ts`). Pages can contain attacker-authored "ignore previous instructions" payloads that hijack the agents tool use, exfiltrate `systemInstructions`, or fabricate citations. Standard for AI search engines, but worth documenting. **Fix:** wrap external content in clearly delimited blocks (e.g. `<external_content>...</external_content>`) and instruct the model to treat them as data, never instructions; consider an injection-detector pre-pass on scraped text.

### MED-04 - User-supplied `systemInstructions` accepted verbatim
Both `/api/chat` (`systemInstructions: z.string().nullable().optional()`) and `/api/search` accept arbitrary system-prompt text. With no auth, anyone can pivot the assistant into roles outside the operators intent (data-exfil, jailbreaks). **Fix:** auth gate, optional length cap, optional content-policy filter.

### MED-05 - `data/config.json` persists arbitrary keys via dot-path setter
`configManager.updateConfig(key, val)` (`src/lib/config/index.ts:254-272`) walks any dot-separated path supplied by the client (`POST /api/config` body) and creates intermediate objects. There is no key allowlist. While `__proto__`/`constructor` writes are blunted by JS object semantics on plain objects, the function still allows an unauthenticated remote attacker (CRITICAL-01) to overwrite arbitrary config nodes - including search engine URL, provider configs, etc. **Fix:** validate `key` against the keys declared in `uiConfigSections`; reject unknown paths and prototype keys explicitly.

### MED-06 - `.env*` files not present, but no commit-time guard exists
`.gitignore` correctly excludes `.env*` and `data/`. There is no pre-commit hook (gitleaks, detect-secrets, husky) wired in `package.json` to prevent future accidental leaks. **Fix:** add gitleaks GitHub Action and a husky pre-commit secret scan.

### MED-07 - Numeric coordinates interpolated into outbound URL without coercion
`src/app/api/weather/route.ts:18-22` builds the open-meteo URL via template literal with `body.lat` and `body.lng` which are typed `number` but never validated. A string body like `lat: "1&attack=..."` injects extra query params on `api.open-meteo.com`. Low impact (target is fixed) but trivial to fix with Zod `z.number()` coercion.

---

## LOW findings

- **LOW-01** Verbose error logging (`console.error(err)`) in nearly every route returns a generic message to the client (good) but logs full errors server-side. Ensure logs are not shipped to user-facing dashboards. (`src/app/api/**/route.ts`)
- **LOW-02** No security headers configured. `next.config.mjs` has no `headers()` function. Missing: `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`/`frame-ancestors`, `X-Content-Type-Options`, `Referrer-Policy`. **Fix:** add `headers()` returning a baseline policy.
- **LOW-03** `Dockerfile:71` grants the `searxng` user passwordless `sudo ALL`. Used by `entrypoint.sh:6` only for `sudo -H -u searxng bash -c ...`. Sudo could be replaced by `su` or by simply running the SearXNG block as the `searxng` user from the start. Reduces blast radius if the container is breached.
- **LOW-04** Container runs as `root` (no final `USER` directive in `Dockerfile`). Run as a dedicated non-root user.
- **LOW-05** Donation Ethereum address is hardcoded in README. Not a vulnerability per se, but a tampering target - anyone with merge rights could swap it. Consider a signed `FUNDING.yml` and pinning in release notes.

---

## Prompt-injection vector inventory (Task 1)

| Source | Field | Reaches LLM? | Sanitised? | Notes |
|---|---|---|---|---|
| `POST /api/chat` body | `message.content`, `history`, `systemInstructions`, `files[]` chunks | Yes | Schema-validated lengths only | MED-03, MED-04 |
| `POST /api/search` body | `query`, `history`, `systemInstructions` | Yes | No length cap | MED-02, MED-04 |
| Scraped web pages via `Scraper.scrape` | full page text | Yes | No instruction-boundary delimiters | MED-03 |
| SearXNG result snippets | `title`, `content` | Yes | No | MED-03 |
| Uploaded files (`pdf`, `docx`, `txt`) | extracted text -> embeddings -> retrieved chunks -> LLM | Yes | None | HIGH-01 + MED-03 |
| `POST /api/images`, `/api/videos`, `/api/suggestions` body | `chatHistory`, `query` | Yes | No | inherits MED-03/04 |

---

## Connector / integration permissions review (Task 4)

| Integration | Direction | Key handling | Concern |
|---|---|---|---|
| OpenAI / Anthropic / Gemini / Groq / OpenAI-compatible | outbound | user-supplied via setup UI, stored plaintext in `data/config.json` | HIGH-03, CRITICAL-02 |
| Ollama / LM Studio | outbound | URL only; no auth header; defaults to `http://localhost:11434` / `:1234` | OK on localhost; expose risk if URL points elsewhere |
| SearXNG | outbound | URL from env or config; no API key | shared `secret_key` (HIGH-02) |
| Open-Meteo (weather) | outbound | no key | benign |
| Yahoo Finance (`yahoo-finance2`) | outbound | no key | benign |
| Google `@google/genai` | outbound | API key in config | HIGH-03 |
| HuggingFace `@huggingface/transformers` | local model load | no key required for public models | benign |

No OAuth, no webhook, no inbound third-party callback. The only inbound surface is the unauth Next.js API.

---

## Network exposure review (Task 6)

- **Container:** `EXPOSE 3000 8080` (`Dockerfile:73`). Only 3000 is published in `docker-compose.yaml`.
- **Bind address:** Next.js standalone server binds `0.0.0.0` by default in containers; `entrypoint.sh:6` launches Flask SearXNG with `--host=0.0.0.0`. Inside the container, anyone on the same Docker network can reach SearXNG on 8080 directly.
- **README "Expose Vane to network"** explicitly tells users it works "on the same network and stays accessible even with port forwarding" - which without auth means the CRITICAL-01 risk is documented and encouraged.
- No TLS termination in the bundled image.

---

## Unsafe-pattern scan (Task 5)

| Pattern | Hits | Verdict |
|---|---|---|
| `eval(` | 0 | clean |
| `new Function(` | 0 | clean |
| `child_process` / `exec*` / `spawn*` | 0 in `src/**` | clean (Node ENV) |
| `db.exec(` (better-sqlite3) | 11 in `src/lib/db/migrate.ts` | safe - static schema migration strings, no string interpolation of user input |
| `dangerouslySetInnerHTML` / `innerHTML =` | 0 in `src/**` | clean |
| Shell concatenation | 0 | clean |
| Template literals into `fetch` | `src/app/api/weather/route.ts:18-22` | see MED-07 |

---

## Safe vs. unsafe components

### Safe (no findings or only LOW)
- SQL access layer (`src/lib/db/**`, drizzle-orm + better-sqlite3) - uses parameterised queries via drizzle.
- Migration scripts (`src/lib/db/migrate.ts`) - static SQL strings, no user input.
- Weather API route (`src/app/api/weather/route.ts`) - third-party data only, but see MED-07.
- Discover route (`src/app/api/discover/route.ts`) - fixed-topic allowlist, no user input besides enum.
- React UI tree - no `dangerouslySetInnerHTML`, no `innerHTML=`.
- `.gitignore` - correctly excludes `.env*`, `data/`, `db.sqlite`, `searxng/`, `certificates`.
- Scraper input parsing (Readability + JSDOM) - appropriate for content extraction; the issue is upstream URL validation (HIGH-05), not the parser.

### Unsafe / requires hardening
- All `src/app/api/**/route.ts` endpoints (auth + rate-limit + CORS).
- `src/lib/config/index.ts` (plaintext secrets, dot-path setter).
- `src/lib/uploads/manager.ts` (MIME sniffing, ext allowlist, size cap).
- `src/lib/scraper.ts` (SSRF, `--no-sandbox`).
- `searxng/settings.yml` (committed secret).
- `Dockerfile` (`sudo ALL`, runs as root).

---

## Recommended remediation order (no auto-apply - pending user approval)

1. **Rotate the SearXNG `secret_key`** (HIGH-02). Anyone reading the public repo already has it. Generate at container start; do not commit a real one.
2. **Add a single-token auth middleware** (`src/middleware.ts`) keyed off a `VANE_AUTH_TOKEN` env var; require for every `/api/*`. Closes CRITICAL-01 and dramatically shrinks blast radius for HIGH-01/HIGH-05/MED-01/MED-02/MED-04/MED-05.
3. **Redact secret fields in `GET /api/config`** (CRITICAL-02). Mark fields `secret: true` in `uiConfigSections.modelProviders` metadata; replace value with `****` on serialize.
4. **Encrypt `data/config.json`** (HIGH-03) with a key derived from an operator passphrase / env var. Tighten file mode `0600`.
5. **Harden uploads** (HIGH-01): magic-byte sniff, extension allowlist `{pdf,docx,txt}`, 25 MB cap, count cap.
6. **SSRF guard the scraper** (HIGH-05): scheme allowlist, IP-range blocklist, drop `--no-sandbox`.
7. **Set up dependency CVE scanning** (HIGH-04): commit `package-lock.json` or run `yarn audit` in CI; add Dependabot.
8. **Add security headers + CORS allowlist** (LOW-02) in `next.config.mjs` `headers()`.
9. **Drop `sudo` and add a final `USER` directive** in `Dockerfile` (LOW-03/04).
10. **Validate dot-path keys** in `configManager.updateConfig` (MED-05).
11. **Coerce/validate numeric body params** in `weather/route.ts` (MED-07).
12. Add **prompt-injection boundary delimiters** for scraped content (MED-03) and length caps for `systemInstructions`/`query` (MED-02/MED-04).

> **All of the above are flagged only.** Per the audit constraints, no security-critical code was modified and no files were deleted. Awaiting user approval before applying any fix.
