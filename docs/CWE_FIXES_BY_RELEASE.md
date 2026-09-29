# Questarr — CWEs addressed per release (v1.2.0 → v1.5.0)

Method: same as [`docs/CVE_FIXES_BY_RELEASE.md`](CVE_FIXES_BY_RELEASE.md) — diffed `package-lock.json` at each
tag boundary and cross-checked every bumped package through OSV.dev. Each advisory is then mapped to its CWE
IDs sourced from the `database_specific.cwe_ids` field in the OSV.dev response (e.g. `["CWE-400", "CWE-770"]`;
older records used `database_specific.cwes`). The script that automates this
process is `scripts/cwe-report.mjs`.

This document gives a **weakness-category view** of what was addressed across releases — useful for tracking
which classes of bugs (injection, DoS, memory safety, SSRF, …) were systematically reduced over time. The
companion CVE doc lists the same findings by severity and package. The two documents are complementary;
neither replaces the other.

Scope note: same as the CVE doc — this covers dependency-bump _fixes_, not a full current-exposure audit.
First-party code weaknesses are tracked separately in [`docs/SECURITY_ASSESSMENT.md`](SECURITY_ASSESSMENT.md)
and [`docs/THREAT_MODEL.md`](THREAT_MODEL.md).

---

## v1.2.0 (from v1.1.0)

### CWE-400: Uncontrolled Resource Consumption

- **fast-xml-parser** 5.3.3 → 5.3.4 — CVE-2026-25128 — numeric entity parsing caused a RangeError DoS;
  no upper bound on expansion count.

---

## v1.2.1 (from v1.2.0)

### CWE-1333: Inefficient Regular Expression Complexity

- **fast-xml-parser** 5.3.4 → 5.3.5 — CVE-2026-25896 — regex injection in DOCTYPE entity names allowed an
  attacker to craft a payload triggering catastrophic backtracking; classified as injection-via-regex (ReDoS).

---

## v1.2.2 (from v1.2.1)

### CWE-400: Uncontrolled Resource Consumption

- **fast-xml-parser** 5.3.5 → 5.3.7 — CVE-2026-26278 — entity expansion in DOCTYPE had no recursion depth
  limit, enabling unbounded memory growth via a small document.

---

## v1.3.0 (from v1.2.2) — largest security-relevant release

### CWE-89: Improper Neutralization of Special Elements used in an SQL Command

- **drizzle-orm** 0.45.1 → 0.45.2 — CVE-2026-39356 — SQL identifiers were not properly escaped, allowing
  injection via user-controlled column/table names passed to query builders.

### CWE-91: XML Injection

- **fast-xml-parser** 5.3.7 → 5.7.1 — CVE-2026-41650 — XML comment and CDATA delimiters were not escaped in
  XMLBuilder output, allowing injected markup when user data flowed through the serialiser.

### CWE-290: Authentication Bypass by Spoofing

- **express-rate-limit** 8.2.1 → 8.3.2 — CVE-2026-30827 — IPv4-mapped IPv6 addresses (e.g. `::ffff:1.2.3.4`)
  were not normalised to their IPv4 form, giving dual-stack clients two independent rate-limit buckets and
  allowing effective bypass of per-client limits.

### CWE-295: Improper Certificate Validation

- **node-forge** 1.3.3 → 1.4.0 — CVE-2026-33896 — `basicConstraints` and RFC 5280 path-length constraints
  were not validated during certificate-chain building, enabling a crafted intermediate to forge a trusted leaf
  certificate.

### CWE-347: Improper Verification of Cryptographic Signature

- **node-forge** 1.3.3 → 1.4.0 — CVE-2026-33894 — RSA-PKCS1 v1.5 signature verification was susceptible to a
  Bleichenbacher-style chosen-ciphertext attack, allowing signature forgery without the private key.
- **node-forge** 1.3.3 → 1.4.0 — CVE-2026-33895 — Ed25519 signature verification did not check for canonical
  scalar encoding, allowing signature malleability (different byte sequences passing for the same signature).

### CWE-400: Uncontrolled Resource Consumption

- **fast-xml-parser** 5.3.7 → 5.7.1 — CVE-2026-33036 — incomplete fix for CVE-2026-26278; a numeric entity
  bypass re-enabled unbounded expansion even when a limit was configured.
- **fast-xml-parser** 5.3.7 → 5.7.1 — CVE-2026-33349 — entity expansion limit treated as JS falsy when set
  to `0`, silently disabling all protection.
- **multer** 2.0.2 → 2.1.1 — CVE-2026-2359 — resource exhaustion via concurrent upload requests with
  pathological field layouts.
- **multer** 2.0.2 → 2.1.1 — CVE-2026-3304 — incomplete cleanup of aborted uploads consumed disk space until
  the process ran out of writable storage.
- **socket.io-parser** 4.2.5 → 4.2.6 — CVE-2026-33151 — unbounded binary attachments in Socket.IO messages
  were buffered in memory without any size limit, enabling memory exhaustion DoS.

### CWE-459: Incomplete Cleanup

- **multer** 2.0.2 → 2.1.1 — CVE-2026-3304 — see CWE-400 entry above; incomplete cleanup of aborted uploads
  is classified under both resource consumption and incomplete cleanup.

### CWE-674: Uncontrolled Recursion

- **fast-xml-parser** 5.3.7 → 5.7.1 — CVE-2026-27942 — `XMLBuilder` with `preserveOrder: true` recursed into
  nested structures without a depth guard, causing a stack overflow on deeply nested input.
- **multer** 2.0.2 → 2.1.1 — CVE-2026-3520 — uncontrolled recursion when parsing multipart payloads with
  deeply nested boundary markers; exploitable with a crafted ~4 KB request body.

### CWE-835: Loop with Unreachable Exit Condition (Infinite Loop)

- **node-forge** 1.3.3 → 1.4.0 — CVE-2026-33891 — `BigInteger.modInverse(0)` entered an infinite loop with no
  exit path; reachable via crafted RSA public keys or DH parameters.

---

## v1.3.1 (from v1.3.0)

No dependency bump in this release crosses a `fixed` OSV boundary — no CWE fixes to attribute.

---

## v1.4.0 (from v1.3.1)

### CWE-20: Improper Input Validation

- **qs** 6.14.2 → 6.15.2 — CVE-2026-8723 — `qs.stringify` threw an uncaught `TypeError` when it encountered
  `null`/`undefined` array entries with `encodeValuesOnly` set; missing input guard turned invalid data into a
  remotely-triggerable DoS.

### CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal) _(devDep)_

- **vite** 8.0.12 → 8.1.4 — CVE-2026-53571 — `server.fs.deny` allow-list bypass; crafted paths using URL
  encoding evaded the restriction and allowed arbitrary file reads from the dev server's host filesystem.

### CWE-93: Improper Neutralization of CRLF Sequences

- **form-data** 4.0.5 → 4.0.6 — CVE-2026-12143 — multipart field names and filenames were passed through to
  MIME headers without stripping `\r\n` sequences, allowing header injection in any HTTP client that consumed
  the generated body (e.g. proxied upload forwarding).

### CWE-200: Exposure of Sensitive Information to an Unauthorised Actor _(devDep)_

- **vite** 8.0.12 → 8.1.4 — CVE-2026-53632 — the `launch-editor` integration passed user-supplied paths
  through to an OS shell command on Windows; a UNC path could be crafted to trigger an outbound SMB connection
  and capture an NTLMv2 authentication hash from the developer's machine.

### CWE-400: Uncontrolled Resource Consumption

- **multer** 2.1.1 → 2.2.0 — CVE-2026-5079 — deeply nested field name arrays (e.g. `a[b][c][…]` repeated
  thousands of times) caused O(n²) processing and memory growth, eventually OOM-killing the process.
- **ws** 8.18.3 → 8.21.0 — CVE-2026-48779 — the receiver reassembled fragmented frames and tiny data chunks
  without a per-message size cap, allowing memory exhaustion from a stream of small messages.

### CWE-457: Use of Uninitialized Variable

- **ws** 8.18.3 → 8.21.0 — CVE-2026-45736 — a buffer slice was returned to callers before being zeroed,
  leaking up to 124 bytes of adjacent heap content from a prior message in the same allocation region.

### CWE-459: Incomplete Cleanup

- **multer** 2.1.1 → 2.2.0 — CVE-2026-5038 — aborted uploads left temporary files on disk; the cleanup path
  was skipped when the request was destroyed before the `finish` event fired.

### CWE-770: Allocation of Resources Without Limits or Throttling

- **brace-expansion** 5.0.6 → 5.0.7 — CVE-2026-45149 — a crafted large numeric range (e.g. `{1..999999999}`)
  bypassed the documented DoS protection; the guard checked only the final count, not intermediate string
  lengths, so the per-item buffer could exhaust memory before the limit was tested.

### CWE-1333: Inefficient Regular Expression Complexity

- **js-yaml** 4.1.1 → 5.2.1 — CVE-2026-53550 — YAML merge keys (`<<`) with repeated alias references caused
  O(n²) work during parsing; a payload under 10 KB could delay processing by several seconds.

---

## v1.4.1 (from v1.4.0) — hotfix

### CWE-400: Uncontrolled Resource Consumption

- **brace-expansion 5.0.7 → 5.0.9** — CVE-2026-14257 (GHSA-mh99-v99m-4gvg) — brace-expansion DoS via unbounded expansion length causing an out-of-memory process crash
- **brace-expansion 5.0.7 → 5.0.9** — CVE-2026-13149 (GHSA-3jxr-9vmj-r5cp) —
- **brace-expansion 5.0.7 → 5.0.9** — CVE-2026-69152 (GHSA-rgw5-rvv9-x895) — brace-expansion: DoS via unbounded intermediate arrays, bypassing the CVE-2026-14257 mitigation

### CWE-407: Inefficient Algorithmic Complexity

- **brace-expansion 5.0.7 → 5.0.9** — CVE-2026-13149 (GHSA-3jxr-9vmj-r5cp) —
- **js-yaml 5.2.1 → 5.2.2** — CVE-2026-73643 (GHSA-pm4m-ph32-ghv5) — js-yaml: Exponential parsing time in the flow collections leads to denial of service

### CWE-436: Interpretation Conflict

- **fast-uri 3.1.3 → 3.1.4** — CVE-2026-16221 (GHSA-v2hh-gcrm-f6hx) — fast-uri vulnerable to host confusion via literal backslash authority delimiter _(devDep)_

### CWE-770: Allocation of Resources Without Limits or Throttling

- **brace-expansion 5.0.7 → 5.0.9** — CVE-2026-14257 (GHSA-mh99-v99m-4gvg) — brace-expansion DoS via unbounded expansion length causing an out-of-memory process crash
- **brace-expansion 5.0.7 → 5.0.9** — CVE-2026-69152 (GHSA-rgw5-rvv9-x895) — brace-expansion: DoS via unbounded intermediate arrays, bypassing the CVE-2026-14257 mitigation
- **body-parser 1.20.5 → 1.20.6** — CVE-2026-12590 (GHSA-v422-hmwv-36x6) — body-parser vulnerable to denial of service when invalid limit value silently disables size enforcement

### CWE-776: Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')

- **fast-xml-parser 5.10.0 → 5.10.1** — CVE-2026-73569 (GHSA-8r6m-32jq-jx6q) — fast-xml-parser: Repeated DOCTYPE declarations reset entity expansion limits

---

## v1.4.2 (from v1.4.1) — hotfix tag off v1.4.1

### CWE-20: Improper Input Validation

- **ip-address 10.2.0 → 10.5.0** — CVE-2026-69192 (GHSA-mwp4-54f8-5fhr) — ip-address: Address4 decodes leading-zero octets as decimal while resolvers decode them as octal, allowing SSRF and trust-boundary bypass
- **ip-address 10.2.0 → 10.5.0** — CVE-2026-54272 (GHSA-22jq-vg5j-6vgg) — ip-address: Misclassification of IPv4-mapped/NAT64 IPv6 addresses can bypass SSRF and trust-boundary checks
- **ip-address 10.2.0 → 10.5.0** — CVE-2026-69198 (GHSA-4xrf-jv44-h6hh) — ip-address: a CIDR suffix on the parsed address suppresses special-use classification and can bypass SSRF and trust-boundary checks
- **socket.io-parser 4.2.6 → 4.2.7** — CVE-2026-69185 (GHSA-2m8v-j782-fhvr) — Socket.IO: Zero-attachment Memory Exhaustion

### CWE-754: Improper Check for Unusual or Exceptional Conditions

- **socket.io-parser 4.2.6 → 4.2.7** — CVE-2026-69185 (GHSA-2m8v-j782-fhvr) — Socket.IO: Zero-attachment Memory Exhaustion

### CWE-918: Server-Side Request Forgery (SSRF)

- **ip-address 10.2.0 → 10.5.0** — CVE-2026-69192 (GHSA-mwp4-54f8-5fhr) — ip-address: Address4 decodes leading-zero octets as decimal while resolvers decode them as octal, allowing SSRF and trust-boundary bypass
- **ip-address 10.2.0 → 10.5.0** — CVE-2026-54272 (GHSA-22jq-vg5j-6vgg) — ip-address: Misclassification of IPv4-mapped/NAT64 IPv6 addresses can bypass SSRF and trust-boundary checks
- **ip-address 10.2.0 → 10.5.0** — CVE-2026-69198 (GHSA-4xrf-jv44-h6hh) — ip-address: a CIDR suffix on the parsed address suppresses special-use classification and can bypass SSRF and trust-boundary checks

---

## v1.5.0 (from v1.4.2)

`proxy-addr` 2.0.7 → 2.0.8 (CVE-2026-90711, CRITICAL) is not yet indexed by OSV.dev, so it carries no CWE here; the Docker base-image fixes (#1113) are OS packages, outside this npm report.

### CWE-20: Improper Input Validation

- **fast-uri 3.1.4 → 3.1.7** — CVE-2026-75975 (GHSA-f65p-4m7j-42xc) — fast-uri vulnerable to server-side request forgery via malformed IPv6 normalization

### CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

- **postcss 8.5.18 → 8.5.28** — CVE-2026-69153 (GHSA-fxqj-rqcc-2cmp) — PostCSS: incomplete fix of CVE-2026-45623 — attacker-controlled sourceMappingURL reads arbitrary .map files when `from` is unset _(devDep)_
- **vitest / @vitest/mocker 4.1.10 → 5.0.1** — CVE-2026-84373 (GHSA-82fw-gwwq-j7x9) — Vitest: Path Traversal / Arbitrary File Read via @vitest/mocker Redirect Mock _(devDep)_

### CWE-116: Improper Encoding or Escaping of Output

- **fast-uri 3.1.4 → 3.1.7** — CVE-2026-84292 (GHSA-qw65-cvwx-89v3) — fast-uri vulnerable to authority injection via an unvalidated port in serialize

### CWE-174: Double Decoding of the Same Data

- **fast-uri 3.1.4 → 3.1.7** — CVE-2026-75899 (GHSA-fph4-wmhf-6fwf) — fast-uri vulnerable to server-side request forgery via repeated hostname percent-decoding

### CWE-177: Improper Handling of URL Encoding (Hex Encoding)

- **fast-uri 3.1.4 → 3.1.7** — CVE-2026-76172 (GHSA-jqff-g426-hqxp) — fast-uri vulnerable to host confusion via percent-encoded scheme normalization

### CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

- **postcss 8.5.18 → 8.5.28** — CVE-2026-69153 (GHSA-fxqj-rqcc-2cmp) — PostCSS: incomplete fix of CVE-2026-45623 — attacker-controlled sourceMappingURL reads arbitrary .map files when `from` is unset _(devDep)_

### CWE-248: Uncaught Exception

- **multer 2.2.0 → 2.4.0** — CVE-2026-77078 (GHSA-wc9g-mqfw-jrwm) — multer vulnerable to Denial of Service via crafted multipart field names
- **qs 6.15.2 → 6.16.0** — CVE-2026-82417 (GHSA-4mjr-xmp4-gh2g) — qs.stringify throws TypeError on objects with a non-callable constructor.isBuffer property
- **undici 8.10.0 → 8.10.2** — CVE-2026-85024 (GHSA-3wwx-pv8p-q78v) — undici vulnerable to Denial of Service via unhandled error in WebSocket permessage-deflate decompression
- **browserslist 4.28.4 → 4.28.9** — CVE-2026-73088 (GHSA-73wf-gq98-2v4g) — Browserslist: Uncaught crash / prototype write via untrusted browserslist-stats.json custom stats (normalizeStats) _(devDep)_
- **undici (node-gyp) 6.28.0 → 6.29.0** — CVE-2026-85024 (GHSA-3wwx-pv8p-q78v) — undici vulnerable to Denial of Service via unhandled error in WebSocket permessage-deflate decompression _(devDep)_

### CWE-362: Race Condition

- **multer 2.2.0 → 2.4.0** — CVE-2026-77063 (GHSA-qvfw-j98x-7q72) — multer vulnerable to file size limit bypass via async fileFilter race condition

### CWE-400: Uncontrolled Resource Consumption

- **multer 2.2.0 → 2.4.0** — CVE-2026-82333 (GHSA-535w-7cp7-47q4) — multer vulnerable to Denial of Service via oversized array index in field names
- **multer 2.2.0 → 2.4.0** — CVE-2026-77037 (GHSA-qfvm-cv95-jqjf) — multer vulnerable to Denial of Service via file descriptor leak on aborted uploads
- **multer 2.2.0 → 2.4.0** — CVE-2026-88932 (GHSA-3pph-fpjx-jg34) — multer vulnerable to Denial of Service via orphaned disk writes on aborted uploads
- **js-yaml 4.3.0 → 4.3.2** — CVE-2026-84375 (GHSA-2883-xcg3-v3hh) — js-yaml: maxTotalMergeKeys does not limit CPU use for empty merge sources _(devDep)_

### CWE-407: Inefficient Algorithmic Complexity

- **js-yaml 4.3.0 → 4.3.2** — GHSA-5p4m-2wfm-xmqj — JS-YAML: Quadratic CPU consumption in !!omap resolution (3.x and 4.x) — CVE-2026-59870 fix not backported _(devDep)_
- **js-yaml 4.3.0 → 4.3.2** — CVE-2026-84375 (GHSA-2883-xcg3-v3hh) — js-yaml: maxTotalMergeKeys does not limit CPU use for empty merge sources _(devDep)_

### CWE-436: Interpretation Conflict

- **fast-uri 3.1.4 → 3.1.7** — CVE-2026-18446 (GHSA-7p8r-x3mc-p8w7) — fast-uri vulnerable to host confusion via backslash authority introducer
- **fast-uri 3.1.4 → 3.1.7** — CVE-2026-75931 (GHSA-5jgf-p345-68v8) — fast-uri vulnerable to host confusion via skipped IDN canonicalization on scheme-relative references

### CWE-459: Incomplete Cleanup

- **multer 2.2.0 → 2.4.0** — CVE-2026-77037 (GHSA-qfvm-cv95-jqjf) — multer vulnerable to Denial of Service via file descriptor leak on aborted uploads
- **multer 2.2.0 → 2.4.0** — CVE-2026-88932 (GHSA-3pph-fpjx-jg34) — multer vulnerable to Denial of Service via orphaned disk writes on aborted uploads

### CWE-697: Incorrect Comparison

- **ip-address 10.5.0 → 10.7.2** — CVE-2026-101913 (GHSA-rpw4-54j3-4h4q) — ip-address: Address6.isLinkLocal() recognizes fe80::/64 rather than fe80::/10, allowing SSRF and trust-boundary bypass to on-link hosts

### CWE-703: Improper Check or Handling of Exceptional Conditions

- **qs 6.15.2 → 6.16.0** — CVE-2026-82417 (GHSA-4mjr-xmp4-gh2g) — qs.stringify throws TypeError on objects with a non-callable constructor.isBuffer property

### CWE-705: Incorrect Control Flow Scoping

- **baseline-browser-mapping 2.10.40 → 2.11.21** — CVE-2026-45819 (GHSA-w5vr-8v7q-w6rv) — _(devDep)_

### CWE-755: Improper Handling of Exceptional Conditions

- **baseline-browser-mapping 2.10.40 → 2.11.21** — CVE-2026-45819 (GHSA-w5vr-8v7q-w6rv) — _(devDep)_

### CWE-770: Allocation of Resources Without Limits or Throttling

- **qs 6.15.2 → 6.16.0** — CVE-2026-82562 (GHSA-x5fp-wj9c-mxmx) — qs.parse does not enforce arrayLimit on comma groups under bracket-push keys when throwOnLimitExceeded is set (incomplete fix for CVE-2026-2391)
- **browserslist 4.28.4 → 4.28.9** — CVE-2026-73089 (GHSA-c83g-rgw3-j3cx) — Browserslist: Unbounded memory growth (no cache eviction) via distinct query results, leading to eventual OOM _(devDep)_

### CWE-835: Loop with Unreachable Exit Condition ('Infinite Loop')

- **nanoid 3.3.12 → 3.3.18** — CVE-2026-67214 (GHSA-28wg-ghj8-5hjv) — nanoid Infinite Loop via Negative Size in non-secure module _(devDep)_
- **nanoid 3.3.12 → 3.3.18** — CVE-2026-67213 (GHSA-2v37-7h3g-55p8) — nanoid before 5.1.6 Infinite Loop via Zero Size in customAlphabet and customRandom _(devDep)_

### CWE-918: Server-Side Request Forgery (SSRF)

- **fast-uri 3.1.4 → 3.1.7** — CVE-2026-75975 (GHSA-f65p-4m7j-42xc) — fast-uri vulnerable to server-side request forgery via malformed IPv6 normalization
- **fast-uri 3.1.4 → 3.1.7** — CVE-2026-75899 (GHSA-fph4-wmhf-6fwf) — fast-uri vulnerable to server-side request forgery via repeated hostname percent-decoding
- **ip-address 10.5.0 → 10.7.2** — CVE-2026-101913 (GHSA-rpw4-54j3-4h4q) — ip-address: Address6.isLinkLocal() recognizes fe80::/64 rather than fe80::/10, allowing SSRF and trust-boundary bypass to on-link hosts
- **ip-address 10.5.0 → 10.7.2** — CVE-2026-101910 (GHSA-2vr4-cq9g-pvrc) — ip-address: no classifier recognizes the NAT64 local-use range 64:ff9b:1::/48, allowing SSRF and trust-boundary bypass

### CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')

- **browserslist 4.28.4 → 4.28.9** — CVE-2026-73088 (GHSA-73wf-gq98-2v4g) — Browserslist: Uncaught crash / prototype write via untrusted browserslist-stats.json custom stats (normalizeStats) _(devDep)_

---

## Footnote: devDependencies (build-time only, not shipped to production)

The CWE entries marked _(devDep)_ above apply only to tooling that runs at build time (Vite, esbuild,
secretlint). They don't affect the deployed server. Included for completeness so `npm audit` is fully clean.

### CWE-22: Improper Limitation of a Pathname to a Restricted Directory _(devDep)_

- **esbuild** 0.27.2 → 0.27.3 (v1.2.1) — GHSA-g7r4-m6w7-qqqr — the esbuild dev server served arbitrary files
  outside the configured root on Windows when path traversal sequences were used in asset requests. Fixed
  properly in 0.28.1 (v1.4.0). A separate advisory (GHSA-67mh-4wv8-2f99) in the `@esbuild-kit/core-utils`
  nested copy covered permissive cross-origin request handling (related CWE-942).
- **vite** 5.4.21 → 8.0.9 (v1.3.0) — CVE-2026-39365 — path traversal in optimised-deps `.map` handling
  (build-time only).

---

_To regenerate this report, run `node scripts/cwe-report.mjs` after fetching all `v*` tags (`git fetch --tags`).
To save a specific range: `node scripts/cwe-report.mjs v1.3.0 v1.4.0`. OSV.dev is queried live; network access
is required._
