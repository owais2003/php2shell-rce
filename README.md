```
 ____  _   _ ____ ____  ____  _   _ _____ _     _
|  _ \| | | |  _ \___ \/ ___|| | | | ____| |   | |
| |_) | |_| | |_) |__) \___ \| |_| |  _| | |   | |
|  __/|  _  |  __// __/ ___) |  _  | |___| |___| |___
|_|   |_| |_|_|  |_____|____/|_| |_|_____|_____|_____
                  author: owais_omar
```

# PHP2Shell — Handler-Mismatch RCE: Findings, Lab & POC Assessment

**TL;DR:** The PHP2Shell "handler-mismatch → `__destruct`" POC is **correct** and achieves
**unauthenticated RCE**. It was reproduced end-to-end in a local lab
(Apache 2.4.65 + mod_php **8.4.11**) **4/4** with random session IDs. The exploit is
pre-auth, needs no OOM/heap calibration, and hinges on a **serialize-handler mismatch**
between two web roots.

- **Vulnerability class:** session-extension serialize-handler mismatch → object injection → `__destruct()`
- **Related CVEs:** `CVE-2026-115560` (this chain), `CVE-2026-109618` / `CVE-2026-109619` (the "other" OOM chain)
- **Verified on:** PHP 8.2.34 (POC author) · reproduced here on PHP 8.4.11
- **SAPI:** mod_php (verified) · php-cgi / php-fpm (expected)

---

## 1. The RCE Chain (confirmed against PHP 8.2 **and** 8.4 source)

The `php` session handler's **decode** function is byte-identical between PHP 8.2 and 8.4,
so the 8.4.11 lab is a faithful stand-in for the POC's 8.2.34 target.

The exploit is **two unauthenticated HTTP requests**:

### [1] SEED — inject the object into a session key
`POST` multipart to a directory whose `session.serialize_handler = php_serialize`
**and** `session.upload_progress.cleanup = Off`, with:

- `PHPSESSID=<sid>` — session fixation via the **POST body** (the session-fixation bug)
- `PHP_SESSION_UPLOAD_PROGRESS=|<payload>` — payload with a **leading `|`**
- one file part

The rfc1867 upload-progress callback (in `session.c`) fixes the session ID from the POST
body and stores the key **`upload_progress_|<payload>`** verbatim. The session is flushed
to disk *during* the upload. The actual blob written:

```
a:1:{s:78:"upload_progress_|O:6:"Logger":1:{s:3:"cmd";s:26:"...";}";a:5:{s:10:"start_time";i:...;...}}
```

The injected `|<payload>` sits **inside the key**.

### [2] FIRE — mis-decode triggers `__destruct()`
`GET` a directory whose `session.serialize_handler = php`, with `Cookie: PHPSESSID=<sid>`.
`session_start()` decodes with the `php` handler, which **naively splits at the first `|`**:

- key   = `a:1:{s:78:"upload_progress_`
- value = `O:6:"Logger":1:{...}`  → **unserialized into a live `Logger` object**
- the trailing `";a:5:{...}` has no `|` → scan hits end → **decode FAILURE**
- → `PHP_VAR_UNSERIALIZE_DESTROY()` → refcount drops → **`__destruct()` → `system($cmd)` → RCE**

The command output appears in the FIRE response **before** `FIRED_OK`, proving
`__destruct()` ran *inside* `session_start()`.

---

## 2. Key Finding: the handler mismatch is **essential**, not cosmetic

The POC is right to emphasize the mismatch, but the *reason* is subtler than "cleaner RCE."
Testing the **no-mismatch** case (both dirs `php`) showed the command **did not run** —
the session file was **0 bytes**. The cause is in the `php` handler's **encode** function:

```c
if (memchr(ZSTR_VAL(key), PS_DELIMITER, ZSTR_LEN(key))) {   /* key contains '|' */
    fail = true; break;                                       /* → NULL → empty session file */
}
```

| Both dirs use… | Outcome |
|---|---|
| `php` | SEED **encode fails** (key has `\|`) → 0-byte file → FIRE reads empty → **no RCE** |
| `php_serialize` | FIRE **decode succeeds** (valid array; payload is just part of the key string) → no object → **no RCE** |
| **`php_serialize` / `php` (mismatch)** | SEED writes blob, FIRE mis-decodes → object → `__destruct` → **RCE** ✅ |

So the SEED dir must use a handler whose **encode** tolerates `\|` in keys
(`php_serialize` / `php_binary`), and the FIRE dir must use `php` (whose **decode**
splits on `\|`). **The mismatch is the whole trick.**

---

## 3. Required Configuration

| Directive | Seed dir | Fire dir | Why |
|---|---|---|---|
| `session.serialize_handler` | `php_serialize` | `php` | the mismatch that triggers `__destruct` |
| `session.upload_progress.cleanup` | `Off` | (any) | keeps the injected key in the saved blob |
| `session.upload_progress.enabled` | `On` (default) | `On` (default) | rfc1867 callback active |
| `session.use_strict_mode` | `0` (default) | `0` (default) | dangling/invalid sid accepted without re-validation |
| `session.save_path` | **shared** | **shared** | FIRE must read the file SEED wrote |
| SAPI | mod_php / cgi / fpm | mod_php / cgi / fpm | worker must survive + `session_start` must decode |

Plus a `fire.php` containing the gadget class + `session_start()` (the seed file can be empty).

> ⚠️ **Debian caveat:** stock PHP defaults `session.serialize_handler` to `php_serialize`,
> but **Debian overrides it to `php`**. Always set the seed dir to `php_serialize`
> explicitly — don't rely on the default.

Config is applied per-directory via `.htaccess` (`php_value …`, needs `AllowOverride All`)
or `.user.ini`. Note `.user.ini` is ignored on some targets — `.htaccess` is more reliable.


---

## 4. Version Boundaries (official php.net advisory)

- **Last vulnerable 8.2.x = 8.2.34** (the POC's target).
- **Oct 21, 2026:** PHP **8.2.35** / 8.4.27 / 8.3.36 / 8.5.12 fixed
  **CVE-2026-109618** (OOM corruption) and **CVE-2026-109619** (stale global state).
- **This handler-mismatch chain = CVE-2026-115560** (session upload progress +
  serialize-handler mismatch), handled in the *regular* cycle — **not** fixed in 8.2.35.
  Official mitigation: `session.upload_progress.enabled=0`.

**Implication:** this chain is *not* closed by the Oct 21 emergency patch (8.2.35) — it
works on 8.2.34 **and** 8.2.35 until CVE-2026-115560 lands in a later release.
(The 8.4.11 lab is unpatched for all three CVEs, consistent with this.)

---

## 5. Does it work on Windows?

**Yes** — with caveats. Every moving part lives in the **session extension core**
(`session.c`), not the OS or SAPI:

- session fixation via the `PHPSESSID` POST body,
- the rfc1867 upload-progress callback,
- the `php` handler encode/decode mismatch.

Caveats for a real Windows box:

1. **SAPI** — POC verified mod_php, *expects* php-fpm. Windows most commonly runs
   **IIS + PHP-CGI/FastCGI** (not explicitly tested by the author, but the mechanism is
   SAPI-independent → expected to work).
2. **Handler mismatch must be configurable** — with IIS + a single `php.ini`, set it
   per-directory via `.user.ini` (CGI/FPM) or `.htaccess` (Apache on Windows).
3. **`system()` uses `cmd.exe`** — use Windows commands (`whoami`, not `id`).
4. **Shared `session.save_path`** — trivial with one `php.ini`.

No hard blocker for Windows — it's a strong "expected yes" rather than a verified one.

---

## 6. Local Lab (reproducible)

```
lab/
├── apache/apache.conf      # self-contained non-root Apache config (port 8091)
├── exploit.py              # the exploit (Python 3 stdlib only, no pip)
└── www/
    ├── seed/seed.php       # empty; the rfc1867 callback does the work
    ├── seed/check.php      # shows per-dir ini values
    ├── fire/fire.php       # Logger gadget + session_start()
    └── fire/check.php
```

### Build & run

```bash
# 1) start the lab (non-root Apache + mod_php on :8091)
apache2 -d /etc/apache2 -f lab/apache/apache.conf

# 2) run the exploit
python3 lab/exploit.py http://127.0.0.1:8091 "id; whoami"

# 3) stop the lab
apache2 -d /etc/apache2 -f lab/apache/apache.conf -k stop
```

### Results

| Run | Result |
|---|---|
| 1–4 | **RCE confirmed 4/4**, random session IDs, pre-auth |
| no-mismatch (both `php`) | 0-byte session file, **no RCE** (negative control) |

---

## 7. Files

- `README.md` — this document (findings + assessment).
- `lab/` — the full reproduction lab (config + endpoints + exploit).

