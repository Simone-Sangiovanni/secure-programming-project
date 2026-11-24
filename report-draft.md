# Secure File Encryption and Management System: Draft Report

ICS0022 Secure Programming, Project 1 (File Manager)

## 1. Introduction

### 1.1 Purpose

`sfm` (Secure File Manager) is a command-line tool that lets each user of a Linux system keep a personal, encrypted **vault**. A user can add files to the vault (encrypting them and securely removing the original), list the vault, retrieve a decrypted copy of a file, and securely delete vault files. Access is protected by a master password and by the operating system's per-user ownership model.

### 1.2 Requirements and scope

The project requirements (Checkpoints 1 to 3) are: a command-line interface; file encryption and decryption with a vetted library; password authentication; input validation and sanitization (including command injection and path traversal); secure memory handling; structured logging that never contains secrets, with generic error messages; per-user access control on every file operation; automated tests; and a threat model, architecture and report.

The tool is a single-user-at-a-time CLI process. It deliberately does not provide sharing between users, networking, password recovery or key escrow. A lost master password means lost data.

### 1.3 Technology

C23 with libsodium 1.0.18 (Argon2id, XChaCha20-Poly1305 secretstream, HMAC-SHA256, secure memory) and libcjson (configuration and log files), built with CMake and Ninja on Debian 13. C was chosen because the course asks for explicit demonstration of secure memory handling; libsodium because it is audited, provides locked memory and constant-time primitives, and has a hard-to-misuse API.

## 2. Implementation

### 2.1 Architecture

The program is one process running with the privileges of the invoking user (no `suid`). The executable is installed once for the system; every user has an isolated environment under their home directory:

| Item | Path | Mode |
|---|---|---|
| Configuration | `~/.config/sfm/sfm.config` | 0600 |
| Vault | `~/.local/share/sfm/vault/*.sfm` | dir 0700, files 0600 |
| Log | `~/.local/state/sfm/sfm.log` | 0600 |

Modules (one directory each under `src/`):

| Module | Responsibility |
|---|---|
| `main` | Start-up sequence, core dumps off, owns the session key |
| `init` | Creates/verifies folders and files with `openat`/`mkdirat`, `O_NOFOLLOW`, owner and mode checks; refuses root |
| `config` | Reads/writes the JSON configuration atomically; validates paths and credential state |
| `auth` | Master password setup and login (Argon2id, HKDF-SHA256, backoff), password prompt without echo |
| `cli` | Argument parsing, interactive shell, tokenizer with quote handling, signal handling and secret registry |
| `validate` | Path validation and canonicalization |
| `commands` | `list`, `encrypt`, `decrypt`, `secure_delete` |
| `filecrypt` | Streams a file through the cipher, chunk by chunk |
| `cipher` | Per-file DEK, key wrapping, authenticated chunked encryption |
| `fileio` | The only code that touches user files: safe open, atomic write, secure delete |
| `log` | JSON Lines audit log |

The data flow is shown in `architecture.jpg` with three trust boundaries: TB1 (user input), TB2 (source and destination files) and TB3 (files on disk).

### 2.2 Start-up and authentication

1. `init_prepare_config` creates `~/.config/sfm` (0700) and a default `sfm.config` if missing and verifies owner and mode.
2. `load_config` parses the file; `init_ensure_storage` creates or verifies the vault and log at the **paths stored in the configuration**.
3. If no master password exists: setup is refused when the vault already contains `*.sfm` files (a deleted configuration must not allow re-initialisation over existing data); otherwise the user chooses a password (8-64 characters, upper, lower, digit, special; entered twice).
4. Login: `master = Argon2id(password, salt)` (libsodium `MODERATE` limits); `verifier = HKDF-SHA256(master, salt, "sfm-verifier-v1")`, compared in constant time with the stored value. The KEK is `HKDF-SHA256(master, salt, "sfm-kek-v1")`. Because the labels differ, the verifier stored on disk reveals nothing about the KEK. Wrong passwords are logged individually and delayed 1, 2, 4 ... 30 s; there is no permanent lockout.

The password is typed with terminal echo disabled and wiped as soon as the keys are derived.

### 2.3 Encryption format and key management

Each file gets a fresh random 32-byte DEK. The DEK is wrapped under the KEK with XChaCha20-Poly1305 and stored in the file header; file contents are encrypted with libsodium `secretstream` in 128 KiB chunks (constant memory, files up to 256 GiB).

```
"SFM1" | version=3 | wrap nonce (24) | wrapped DEK (32+16) | stream header (24) | chunk 1 | ... | last chunk
```

The magic and version are authenticated as associated data for both the wrapped DEK and every chunk. Each chunk has a 17-byte tag and the last chunk carries the FINAL tag, so modification, reordering, truncation and trailing data are all detected. Plaintext is written chunk by chunk but into a temporary file that is removed if any later chunk fails, so a failed decryption leaves nothing behind. Compromising one DEK exposes one file only.

### 2.4 File handling

- **Input validation** (`validate`): absolute paths only; empty, over-long (>= 4096 bytes), trailing-slash, and `.`/`..` paths are rejected. For `encrypt`, the directory part is canonicalized with `realpath()` and the file name is appended; the file itself is never resolved. For `decrypt`, the destination directory is canonicalized and must exist. Vault file names must be plain names (no `/`) ending in `.sfm`.
- **Symlinks, special files, TOCTOU** (`fileio`): files are opened with `O_NOFOLLOW | O_NONBLOCK` and inspected with `fstat` on the descriptor: only regular files owned by the effective user and at most 256 GiB are accepted (FIFOs, devices, directories and foreign-owned files are refused; the FIFO case cannot hang).
- **Atomic output**: data goes to a temporary file in the target directory (mode 0600), is `fsync`ed, and is published with `link()`, which fails if the name exists, so existing files are never overwritten. The source of `encrypt` is securely deleted only after the encrypted file is complete.
- **Secure delete**: overwrite with zeros, `fsync`, `unlink`; works on vault files (by name) and on any file the user owns outside the vault (by absolute path, directory part canonicalized); refuses symlinks, directories, special files and other users' files.
- **No command injection**: the program never calls `system()`, `exec*` or a shell. Arguments from the shell tokenizer are used only as data.

### 2.5 Memory management

Keys, verifier, salt and password buffers are locked (`sodium_mlock`), registered with the termination handler, and wiped with `sodium_memzero` right after use. The password is read with `read(2)` directly into its locked buffer: reading it with `fgets` would leave a second copy in the C library's input buffer, which cannot be wiped (the end-to-end test found exactly that copy before this was changed). The plaintext chunk buffer and the cipher state use `sodium_malloc` (guard pages, locked, zeroed on free). Core dumps are disabled with `setrlimit(RLIMIT_CORE, 0)`. `SIGINT`, `SIGQUIT` and `SIGTSTP` are ignored so the process cannot be suspended or interrupted while echo is off; `SIGTERM` and `SIGHUP` run an async-signal-safe handler that zeroes registered secrets, restores terminal echo and exits with status 128+signal.

### 2.6 Logging and error handling

Each security-relevant event is one JSON object per line with `timestamp` (UTC ISO 8601), `event`, `user` (`uid=N`), `source` (`local` or `local:<tty>`), `outcome` and an optional `target` containing only the sanitized base name. The log is opened with `O_NOFOLLOW` and ownership is verified on the descriptor. Passwords, keys and file contents are never passed to the logger. All JSON is produced by libcjson, so file names cannot break the record format; control characters are replaced. User-facing messages are fixed generic strings per error class; `errno` text and internals are never printed.

### 2.7 Build hardening

PIE, Full RELRO, non-executable stack, stack protector, stack-clash protection, CET (`-fcf-protection`), `_FORTIFY_SOURCE` in non-Debug builds, extensive warnings (`-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wformat=2 ...`), and ASan/UBSan in Debug builds.

## 3. Security Analysis

### 3.1 Threats, mitigations and evidence

The evidence column refers to the sections of `tests/test_sfm.py` (end-to-end test of the real program).

| Threat | Mitigation | Evidence |
|---|---|---|
| Password brute force | Argon2id (256 MiB, 3 passes), exponential backoff, every failure logged | Test 2: delay doubles 1, 2, 4, 8 s; a guess costs an Argon2id run; 10+ failures in the log; no lock-out |
| Weak, empty or very long password | Policy and length limit at setup | Test 1: simple, empty and 65/200/1000-character passwords refused, nothing stored |
| Passwords that try to break the program | Password is only data; never formatted, executed or stored | Test 1 and 2: 13 special-character passwords (format specifiers, `$()`, backticks, SQL, quotes, UTF-8, escape codes, random) work or are refused cleanly, no side effect, no crash |
| Timing attack on verifier | `sodium_memcmp` | Code review (`auth.c`) |
| Stored verifier reveals KEK | HKDF with distinct labels | Code review (`auth.c`) |
| Path traversal | Absolute paths, no `.`/`..`, `realpath` on directories, vault names without `/` | Test 3: relative and `..` paths refused for encrypt, decrypt and secure_delete; symlinked directories resolved to the real path |
| Command injection | No shell or process execution | Test 1 and 3: hostile passwords and file names have no side effect |
| Symlink attack | `O_NOFOLLOW` on the final component | Test 3: symlink refused by encrypt and secure_delete, target untouched; Test 4: log, config and vault replaced by links are refused and nothing is written through them |
| Paths and names that are too long | 1023-character line limit, 4096-byte path limit, file-system name limit | Test 3: refused cleanly, source kept, no temporary file left |
| Access to another user's files | `st_uid == geteuid()` on every open; 0700/0600 | Test 3: `/etc/passwd` refused by encrypt and secure_delete; files created 0600 |
| Overwriting existing files | Output created with `link()`, which fails if the name exists | Test 3: collision in the vault and in the destination refused, existing files unchanged |
| Loss of data on failure | Temporary file, `fsync`, atomic publish; source removed last | Test 3 and 4: no temporary files left after failures |
| Tampering, truncation, wrong key | Authenticated chunks with FINAL tag | Test 4: modified, truncated, extended, random and empty vault files are refused with a generic message, no output |
| Data recovery after delete | Zero overwrite, `fsync`, `unlink` | Test 3: old blocks (read through a hard link) are all zeros after encrypt and after secure_delete; the plaintext is nowhere in the test area |
| Secrets in memory | `sodium_mlock`/`sodium_malloc`, `sodium_memzero`, password read with `read(2)` | Test 3 and 4: the process memory contains neither the file content after encrypt/decrypt/delete nor the passwords after login |
| Secrets in core dumps, suspension | Core dumps off, `SIGINT`/`SIGTSTP` ignored, `SIGTERM` handler | Test 3: core limit 0, process not suspended, `SIGTERM` exits with 143 and restores the terminal |
| Secrets in logs | Only base names; no secrets passed to the logger; JSON escaping | Test 4: no password, wrong guess, file content or directory in the log; valid JSON, required fields, escape characters neutralised |
| Tampered configuration, vault or log | Validation, owner and mode checks, `O_NOFOLLOW`, safe refusal | Test 4: deleted folders/files recreated; corrupted configuration refused with a generic message; permissions repaired; modified verifier or salt never logs in |
| Re-initialisation over an existing vault | Setup refused if `*.sfm` files exist | Test 4: refused, vault untouched, also when the credentials are erased from the configuration |
| Denial of service by lockout | Backoff only, no lockout | Test 2 |

### 3.2 Known limitations and residual risks

- The KEK stays in RAM for the whole session because every operation needs it. A process running as the same user (or root) can read it, for example through `ptrace`; the vault protects data at rest, not against a compromised account.
- `mlock` works on whole pages and does not nest, so unlocking one stack buffer may unlock a page shared with another. The secrets are still wiped immediately; `sodium_malloc` for every secret would remove this weakness.
- The termination handler wipes only the registered buffers; the plaintext chunk and cipher state are freed in normal operation but are not registered, and a `SIGKILL` or crash cannot run any handler.
- Secure delete is a single zero pass and is best-effort on SSDs and journaling or copy-on-write filesystems. Read-only source files cannot be opened for overwriting, so the source is kept and a warning is printed.
- The backoff is per process, so restarting the program resets it; Argon2id cost is the main brute-force defence. The Argon2id limits are compiled in, not stored in the configuration.
- `encrypt` re-opens the source by path to delete it; a same-user process that swaps the file in the short window between encryption and deletion could cause a different file to be wiped.
- The output file is published with `link()`, which requires a filesystem with hard links; the vault directory itself is not `fsync`ed afterwards.
- Existence of a file and ownership failures produce distinguishable messages ("not found" vs "belongs to another user"), a minor information leak to the same user.
- If the log file cannot be written the event is silently dropped, by design, so logging problems never block the user's own files.
- First-run setup ends on a weak or mismatching password and must be restarted.

## 4. Testing

The program is tested end to end by `tests/test_sfm.py`, a Python program that starts the real `sfm` in a pseudo-terminal, types the passwords and commands like a user, and checks the results (about 200 checks, around one minute). Python was chosen on purpose: the test reads like the test specification, and it exercises the program exactly as a user does, including the terminal behaviour (hidden password input, signals) that a unit test would have to fake. Run it with `python3 tests/test_sfm.py build/sfm` or `ctest --test-dir build -V`, as a normal user.

The test is organised like the specification:

1. **Initialization**: simple, empty, very long and special-character master passwords; the valid `MasterPSW1!`.
2. **Access**: the same inputs at the login; brute-force resistance (timing of the growing delay, cost per guess, logging, no lock-out).
3. **Commands**: encrypt, decrypt, secure_delete and exit, including absolute and resolved paths, symlinks, too-long paths, foreign files, and name collisions.
4. **Behavior**: passwords in RAM, secrets in the log, and tampered configuration, vault and log.

"No trace on disk" is verified with a second hard link to the file, read after the operation (it must be all zeros), and by searching the whole test area for the plaintext. "No trace in RAM" is verified by searching the memory of the running process (`/proc/<pid>/mem`) for the plaintext and the passwords, after a positive control shows the scanner can find a known string. The test was also run against deliberately broken code (secure delete without overwrite, symlinks followed, password read through stdio) and failed as expected; it found and led to the fix of one real weakness (a copy of the password left in the C library's input buffer).

It passes against both the Debug (ASan/UBSan) and the Release build. Not covered: the wiping of memory at the moment of exit (the memory of a terminated process cannot be inspected; the wiping is verified in-session and by code review), the `mlock` accounting (visible only in the Release build), and paths between 1024 and 4095 bytes (they cannot be typed, because of the shell line limit).

## 5. Conclusion

The tool implements the required commands with authenticated, per-file-key encryption, a memory-hard password KDF, defence in depth around file access (absolute and canonicalized paths, no symlink following, descriptor-level ownership checks, atomic writes, secure deletion), locked and wiped secret memory, and a structured log that was verified not to contain secrets. The design document, architecture diagram and implementation agree, and the automated tests cover correctness, tamper detection, deletion, authentication failure paths and input-validation edge cases.

The main residual risks are those listed in section 3.2: secrets are necessarily in memory while the user is logged in, secure deletion is best-effort on modern storage, and a few hardening refinements (unbuffered password input, `sodium_malloc` for all secrets, vault directory `fsync`) are documented in `TODO.md` as optional future work.

## Appendix A: User manual

1. Install the dependencies and build (see `README.md`).
2. Run `./build/sfm`. On the first run choose a master password (8-64 characters with upper, lower, digit and special character) and confirm it, then log in. **There is no password recovery.**
3. At the `sfm>` prompt:
   - `encrypt "/absolute/path/to/file"`: encrypts the file into the vault and securely deletes the original.
   - `list`: shows the files in the vault.
   - `decrypt "name.sfm" "/absolute/destination/dir"`: writes the decrypted file to the directory; the vault copy stays; existing files are not overwritten.
   - `secure_delete "name.sfm"`: permanently removes a vault file.
   - `help`, `exit`.
4. Use double quotes around names with spaces. Only absolute paths are accepted.
5. Messages are intentionally generic; details of what happened are in `~/.local/state/sfm/sfm.log`.
