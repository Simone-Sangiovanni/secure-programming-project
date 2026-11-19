# Secure File Manager: Review Report

**Method and limits.** This is a static read of all 28 files against the design doc, the diagram, `TODO.md` and the three checkpoints. I did not compile or run anything, so "correct" means "correct by inspection". I also can't see your git history.

## 1. Verdict

The core is implemented and in good shape. All four commands work as designed, the crypto is sound, and ownership, symlink, atomic-write and logging protections are present. What stands between you and a complete submission is:

- **Missing:** the test suite and the draft report (both Checkpoint 3).
- **Broken documentation:** `README.md` fails the Checkpoint 2 "instructions that work on a clean machine" requirement.
- **Small gaps** between design claims and code, listed in section 3.

## 2. What is correct

| Design / checkpoint requirement | Where | Status |
|---|---|---|
| Per-user isolation, dirs 0700 / files 0600, UID check (`st_uid == geteuid()`) | `init.c`, `fileio.c`, `log.c` | ✅ |
| Refuses to run as root, no suid | `init.c` | ✅ |
| Argon2id, then HKDF-SHA256 with distinct labels for verifier and KEK | `auth.c` | ✅ |
| Constant-time verifier compare (`sodium_memcmp`) | `auth.c` | ✅ |
| Unlimited attempts, exponential backoff (1, 2, 4 … capped at 30 s), no permanent lockout | `auth.c` | ✅ |
| Password wiped right after key derivation | `auth.c` | ✅ |
| Login required after first-run setup | `main.c` | ✅ |
| Missing vault/log recreated at the **configured** paths | `main.c`, `init.c` | ✅ |
| Per-file random DEK wrapped by KEK, XChaCha20-Poly1305, secretstream with FINAL tag | `cipher.c` | ✅ |
| Truncation, reordering, trailing data and wrong key all detected; a failed decrypt leaves no output file | `filecrypt.c`, `cipher.c` | ✅ |
| Atomic output (temp file, `fsync`, `link()`, never overwrites) | `fileio.c` | ✅ |
| Source removed only after successful encryption | `commands.c` | ✅ |
| Secure delete (overwrite, `fsync`, `unlink`), documented as best-effort | `fileio.c` | ✅ |
| `O_NOFOLLOW` and `fstat` on the descriptor (no path TOCTOU on reads) | `fileio.c`, `log.c`, `init.c` | ✅ |
| Plaintext chunk buffer in `sodium_malloc`, buffers zeroed after use | `filecrypt.c` | ✅ |
| Core dumps disabled; SIGTERM/SIGHUP handler zeroes registered secrets and restores terminal echo | `main.c`, `cli.c` | ✅ |
| JSON Lines log with event, user, timestamp, source, outcome; filenames sanitized; no secrets passed to the logger | `log.c` | ✅ |
| Config has all 6 keys; atomic save; partial credentials rejected | `config.c` | ✅ |
| No `system()`/`exec*` anywhere, so no command injection | all | ✅ |
| Hardened build (PIE, RELRO, canary, CET, FORTIFY, sanitizers) | `CMakeLists.txt` | ✅ |

## 3. What is incorrect or incomplete

### A. Must fix (cheap, and graders will notice)

1. **`README.md` is wrong.** Details:
   - It references the nonexistent `./basic_setup.sh`.
   - It runs `./sfm` instead of `./build/sfm`.
   - It says `list` and `secure_delete` aren't implemented and that there is no vault.
   - Its `decrypt` example omits the destination directory.
   - It says "Checkpoint 2" as the status.
   - The init step isn't needed because `sfm` self-initialises.
2. **Failed logins are not logged individually.** `auth_login()` loops until the password is right, and `main.c` logs a single `login` event at the end. Ten wrong guesses followed by a correct one produce one *success* record. A brute-force attempt leaves no trace, which defeats the point of an audit log. Fix: call `log_audit_event(cfg, LOG_EVENT_LOGIN, LOG_OUTCOME_FAILURE, nullptr)` inside the wrong-password branch.
3. **`encrypt` does not canonicalize the input path**, but the design says "canonicalized before use". `validate_absolute_path()` only checks the text, and `O_NOFOLLOW` covers only the last component, so a symlinked parent directory is followed. The impact is low because the UID check still applies. Either `realpath()` the parent directory (keeping the basename so the file itself still isn't followed), or reword the design to say that only the destination directory is canonicalized.
4. **Design doc text out of sync with the code:**
   - Authentication says the verifier is computed with Argon2id. In fact it is HKDF over the Argon2id master key.
   - `libcjson` is not listed with `libsodium`.
   - The log `target` field is not mentioned.
   - "If the vault and/or log exist and config is missing, execution is blocked" is only implemented for a vault containing `.sfm` files (`main.c`). An existing log or an empty vault does not block.
   - The doc says the program is installed at system level, but `CMakeLists.txt` has no `install()` rule. One line fixes it: `install(TARGETS sfm RUNTIME DESTINATION bin)`.
5. **`architecture.jpg`:**
   - It says `config.json`, but the real name is `sfm.config`.
   - "Cancel after use" should read "Wipe after use".
   - The log should be labelled "JSON Lines".
   - The box order (validator, then auth, then access control) doesn't match the code, where login comes first and validation and ownership checks happen inside the commands and `fileio`. Either redraw the flow or add a note that it is conceptual.
6. **No tests** (Checkpoint 3) and **no draft report** (Checkpoint 3).

### B. Should fix (small, real gaps against the design)

| # | Issue | Why it matters | Fix |
|---|---|---|---|
| 7 | Password is read with `fgets(stdin)`, so a copy stays in libc's stdio buffer, which `sodium_memzero` can't reach | "Memory used for password input must be overwritten" is only partly true | `setvbuf(stdin, nullptr, _IONBF, 0)` before reading the password, or read with `read(2)` |
| 8 | `sodium_mlock` on **stack** buffers: Linux `mlock` doesn't nest, and `sodium_munlock` zeroes and unlocks the whole page. Unlocking one buffer can unlock a neighbour, even `main`'s `key` | Locked memory guarantee is weaker than claimed | Allocate secrets with `sodium_malloc` (own pages), or document the limitation |
| 9 | Filenames are printed unsanitized in `cmd_decrypt`, `cmd_secure_delete`, `cmd_encrypt` and error output (`list` and the log are sanitized) | Terminal escape sequences from odd filenames | Reuse `print_sanitized_name()` |
| 10 | `CMD_ERR_NOT_IMPLEMENTED` is still defined | Dead code that contradicts the feature set | Remove it from `commands.h` and `commands.c` |
| 11 | Log record written with two `write()` calls (line, then `\n`) | Two sessions of the same user could interleave lines | Append `\n` to the buffer and write once |
| 12 | After `link()` the vault directory is not `fsync`'d | Design claims no loss of the source on a crash; the new directory entry may not be durable when the source is deleted | `fsync` the directory fd before secure-deleting the source |
| 13 | The termination handler zeroes only registered buffers. The plaintext chunk and `CipherStream` aren't registered, and `.sfm-tmp-*` files are left behind | "Signal handlers zero secrets" is partly true | Document it, or register those buffers |
| 14 | Encrypt reads `size` bytes (fixed at open), then `fileio_secure_delete(path)` **reopens by path** | If the file grew or was swapped in between, the extra data or a different file is destroyed (same-UID only, tiny window) | Document it, or compare `st_ino`/`st_size` before deleting |

### C. Document as known limitations (don't fix)

These suit the Security Analysis section of the report:

- The KEK stays in RAM for the whole session, because it is needed for every operation.
- Secure delete is a single zero pass and is best-effort on SSD, journaling and copy-on-write filesystems. Read-only (0400) source files can't be opened `O_RDWR`, so the source is kept and a warning is printed.
- Backoff is per-process, so restarting resets it.
- Argon2id uses the `MODERATE` limits (256 MiB, 3 passes), which are hardcoded and not stored in the config.
- SIGINT, SIGQUIT and SIGTSTP are ignored, so a long encryption can only be stopped with SIGTERM.
- The decrypt destination is deliberately not owner-checked, so `/tmp` works.
- `link()` fails on filesystems without hard links, which gives a generic write error.
- First-run setup exits on a weak or mismatched password instead of re-prompting.
- "File belongs to another user" and "file not found" are distinguishable, a minor existence leak.
- Logging failures are silently dropped by design.
- The same `has_traversal` function is copied three times (`validate.c`, `config.c`, `init.c`), which is a maintainability point only.

## 4. Checkpoint matrix

| Checkpoint | Result |
|---|---|
| **1** Architecture, threat model, language and libraries, README | Mostly done. Fix the diagram labels, add `libcjson`, and rewrite the README (items 1, 4, 5). |
| **2** CLI, encryption, auth, validation, build instructions | Code ✅. Instructions ❌ until the README is fixed. Commits can't be verified. |
| **3** Secure memory | ~90%: items 7, 8, 13. |
| **3** Validation and sanitization | ~90%: items 3, 9. Path traversal is rejected textually and by `realpath` for destinations; no command injection is possible. |
| **3** Logging, generic errors | ~90%: items 2, 11. The "verify no secret is logged" step needs a test. |
| **3** Per-user access control | ✅ |
| **3** Tests | ❌ missing |
| **3** Draft report | ❌ missing (Section 1.3 of the brief wasn't uploaded, so I can't confirm the structure) |

## 5. Minimal test plan

Keep this small. You need these cases to cover the checkpoint:

- **Crypto round-trip** (C test linking `filecrypt`, `cipher`, `fileio` directly, no TTY needed):
  - empty file, 1 byte, exactly 128 KiB, 128 KiB + 1, and a multi-chunk file
  - wrong key, flipped byte in the header and in the body, truncation (a whole chunk cut off), trailing garbage
  - the output file is absent after a failed decrypt
  - existing output is never overwritten
- **Secure delete:** the file is gone, a symlink is refused, another user's or a non-regular file is refused.
- **Validation:** relative path, `..`, `/./`, empty path, trailing `/`, path over 4096, a directory as the file argument, and a missing or non-directory destination.
- **Injection:** filenames containing `;`, `$(...)`, backticks, quotes and newlines are treated as literal data.
- **Authentication** (CLI test through a pty with `expect` or Python's `pty`): wrong password gives backoff and then a correct password succeeds, weak password rejected, mismatch rejected, `EOF` at the prompt.
- **Log hygiene:** run a full session with a known password and file content, then `grep` the log for the password, key bytes and content, and expect no matches. Also check that the log lines are valid JSON.

Two practical tips:

- `read_password()` calls `tcgetattr(stdin)` and fails without a TTY, so the CLI tests need a pty.
- Set `HOME=$(mktemp -d)` in each test (`init.c` honours `$HOME`) so tests never touch your real vault. Note that `reset.sh` runs `rm -rf` on your real vault with no confirmation, so label it dev-only.

## 6. Suggested order

1. Fix the README (item 1).
2. Make the small code fixes (items 2, 7, 9, 10, 11 and optionally 3, 12).
3. Fix the design doc and diagram (items 4, 5), then update `TODO.md`. The old claims about `config.json`, `sodium_mlock`, post-setup login, signal handlers and the HKDF mismatch are now resolved.
4. Write the tests (section 5).
5. Write the draft report, using section 3C as the starting point for the Security Analysis.

If you tell me which steps to take, I can produce them next. A good start is the README plus the code patches for items 2, 7, 9, 10 and 11.