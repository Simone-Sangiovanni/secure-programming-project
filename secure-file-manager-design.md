# Secure File Encryption and Management System, Design Document

## Architecture

The program is designed as an **operating-system-level multi-user application**: each system user has an isolated and independent environment. Each user has their own vault and configuration files, while the executable is unique and installed at the system level (`sudo cmake --install build`, which places it in `/usr/local/bin`), and is therefore shared by all users. This approach leverages the operating system's isolation and ownership mechanisms to prevent users other than the owner from accessing, reading, modifying, or deleting other users' files (with the exception of the system administrator). The program refuses to run as root, so files created in a user's home directory can never end up owned by root.

The system architecture diagram is in `architecture.jpg` (editable source: `architecture.svg`). It shows the components, the data flow, where files and keys live, and three trust boundaries: **TB1** (user input), **TB2** (source and destination files supplied by the user) and **TB3** (the files kept on disk). The module order in the diagram matches the code: CLI, auth (login happens first), input validation, command handlers, crypto, storage; keys live only in locked RAM, and the logger receives non-secret events only.

### Program Startup

When the user runs the program, it checks for the existence of the configuration file, log file, and vault in the user's environment:

- **If the configuration file does not exist**, a default one (XDG paths, no credentials) is created and the program asks the user to create a master password for encrypting and decrypting files. The vault and the log file are then created. **If the vault already contains encrypted files (`*.sfm`), setup is refused**: a lost or deleted configuration must never silently orphan, or be re-initialised over, an existing vault. An existing empty vault or log file is simply verified (owner, permissions) and reused.
- **If the vault and/or log file are missing but the configuration file exists**, the program recreates them at the paths contained in the configuration file.
- **If everything already exists**, the login page is displayed.

After initializing or recreating missing files, the program still displays the login page: first-run setup is always followed by a normal login.

The master password must be 8-64 characters long and contain an uppercase letter, a lowercase letter, a digit and a special character. It is entered twice. If it is too weak or the two entries differ, setup stops with an error and the program must be started again; nothing is stored.

### Login

Login requires entering the master password:

- if the password is correct, the user gains access to the secure file storage;
- if the password is incorrect, the failed attempt is written to the log, the program waits (1 s, 2 s, 4 s, ... capped at 30 s) and the user is prompted again. There is no permanent lockout.

### Actions Available After Login

Once logged in, the user can perform the following actions:

- **list**: lists all encrypted files (`*.sfm`) present in the vault;
- **encrypt `<absolute-path>`**: adds a file to the vault;
- **decrypt `<file-in-vault> <absolute-destination-directory>`**: retrieves a file from the vault;
- **secure_delete `<file-in-vault | absolute-path>`**: securely deletes a file, either a vault file (by name) or any regular file owned by the user outside the vault (by absolute path);
- **help**, **exit**.

Only absolute paths are accepted for files outside the vault. Paths containing `.` or `..` components are rejected, the directory part of the path is canonicalized with `realpath()` (so symbolic links in directories are resolved before use) and the final component is never followed (`O_NOFOLLOW`). File names inside the vault are plain names (no `/`) ending in `.sfm`. Before every file operation, ownership is verified on the opened file descriptor: this means that the user can encrypt/decrypt only their own files and not those belonging to other users. The decryption destination directory is deliberately not required to be owned by the user, so shared folders such as `/tmp` can be used.

Once a file has been encrypted and placed in the vault, the original source file is securely deleted. When a file is decrypted, a destination directory must be specified: the **decrypt operation copies the plaintext file to the specified destination, but keeps the encrypted copy in the vault** (it is not a destructive operation). Existing files are never overwritten. The permanent removal of a file from the vault occurs only through the **secure_delete** command, which securely deletes the encrypted file. The same command can also wipe the user's own files outside the vault; it refuses symbolic links, directories and files of other users.

### Memory Management and Logging

After every encryption/decryption operation, the RAM used is overwritten and freed: the plaintext chunk buffer is allocated with `sodium_malloc` (guard pages, locked, zeroed on free), the cipher state is zeroed, and the password, master key, verifier and per-file DEK buffers are locked with `sodium_mlock` and wiped with `sodium_memzero` immediately after use. The password is read with `read(2)` straight into its locked buffer, so no second copy remains in the C library's input buffer.

Every major action is recorded in the log file without exposing sensitive information. In case of problems, the program terminates in a controlled manner ("crash gracefully"), reporting a generic error and without exposing sensitive information (no `errno` text, paths of other users or stack details).

---

## Threat Model

The following table lists the main threats identified for the system, grouped by area, together with the planned mitigation.

### Authentication

| Threat                                                                        | Mitigation                                                                                                          |
| ----------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Brute-force attack on the master password                                    | Argon2id (libsodium `MODERATE` limits: 3 passes, 256 MiB); unlimited attempts with exponential backoff (1s/2s/4s/... up to 30s); every failed attempt is logged |
| Weak master password                                                          | Length and character-class policy enforced at setup                                                                  |
| Timing attack on verifier comparison                                          | Constant-time comparison (`sodium_memcmp`) instead of direct string comparison                                     |
| Password remaining in memory longer than necessary                           | The plaintext password is zeroed (`sodium_memzero`) immediately after deriving the keys; terminal echo is disabled while typing |
| Denial of service through permanent account lockout after too many attempts  | The backoff is temporary, not a permanent lockout                                                                    |
| Leaking the verifier on disk reveals the encryption key                       | The verifier and the KEK are derived from the master key with HKDF-SHA256 and different labels (`sfm-verifier-v1`, `sfm-kek-v1`), so the stored verifier says nothing about the KEK |

### File Handling

| Threat                                                                      | Mitigation                                                                                                                           |
| --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| Path traversal (`..`, relative paths)                                       | Only absolute paths are accepted; `.`/`..` components are rejected; the directory part is canonicalized with `realpath()`; vault file names must not contain `/` |
| Command injection through file names or arguments                           | The program never starts a shell or another process; arguments are treated as data only                                              |
| Symlink attack (accessing files outside the vault through a symbolic link) | Symlinks are not followed for the file itself (`O_NOFOLLOW`); only regular files are allowed                                         |
| TOCTOU (race condition between checking and using the file)                | File opening followed by `fstat`/ownership verification on the file descriptor, not on the path                                     |
| A user accessing another user's files                                      | Ownership verification (`st_uid == geteuid()`) before every operation on files, config, vault, or log; directories created `0700`, files `0600` |
| Loss of the source file if encryption fails halfway through                | Write to a temporary file, `fsync`, atomic publish into the vault, and only then securely remove the source                         |
| Partial or forged ciphertext accepted on decryption                         | Authenticated chunked encryption with a FINAL tag: truncation, reordering, modification and trailing data are detected; a failed decryption leaves no output file |
| Recovery of sensitive data from deleted files                               | Secure delete: overwrite the contents, `fsync`, then `unlink` (documented as best-effort on SSD/copy-on-write filesystems)         |
| Accidental overwriting of an existing vault during initialization          | If the configuration is missing but the vault already holds encrypted files, setup is refused instead of reinitializing            |

### Key and Password Management

| Threat                                                                  | Mitigation                                                                                                                                                           |
| ----------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Exposure of the master key / DEK / KEK through a memory dump or swap    | Keys are kept in locked memory (`sodium_mlock`, `sodium_malloc`) and zeroed (`sodium_memzero`) as soon as they are no longer needed; the KEK lives only for the session |
| Weak KDF for the master password                                        | Use of Argon2id (memory-hard) instead of simple hashes or checksums                                                                                                  |
| Compromise of a DEK exposing the entire vault                           | Each file has its own DEK, randomly generated and wrapped by the KEK: compromising one DEK does not expose the other files                                            |
| Process crash resulting in a core dump containing secrets               | Core dumps disabled (`setrlimit(RLIMIT_CORE, 0)`); on `SIGTERM`/`SIGHUP` a handler zeroes the registered secret buffers and restores terminal echo; `SIGINT`/`SIGQUIT`/`SIGTSTP` are ignored so the process cannot be suspended with secrets in RAM |
| Secret leakage through logs                                             | Keys, the password, and file contents are never written to logs; logged fields are limited to event, user identifier, timestamp, source, outcome and the sanitized base name of the file |
| Log injection through file names                                        | Control characters are replaced and only the base name is logged; each record is one JSON object per line                           |

---

## Technical Details

The program is written in **C23**, using **libsodium v1.0.18** as the cryptographic library and **libcjson** for the JSON configuration and log files, targeting **Debian 13** for execution.

The program runs as a **single CLI process** with the privileges of the user who invokes it. No `suid` or `root` privileges are required.

### Rationale for the Choices

**C23** was chosen because the course requires an explicit demonstration of secure memory management skills (secure allocation/deallocation, prevention of buffer overflows, use of safe string functions such as `strncpy`/`snprintf`): a low-level language such as C makes these mechanisms visible and verifiable, whereas a memory-safe language would hide them. Compared with previous versions of the standard, C23 provides useful improvements in this context (safer types, `nullptr`, improved compile-time checks), while still remaining a language that requires manual discipline in memory management.

**libsodium** was chosen as the cryptographic library because:

- it provides **audited** and actively maintained implementations of Argon2id, AEADs (AES-256-GCM, XChaCha20-Poly1305), and the HMAC-SHA256 primitive used to build HKDF, avoiding the need to implement cryptographic primitives from scratch;
- it exposes primitives explicitly designed for secure memory and secret management: `sodium_malloc`/`sodium_mlock` for allocating locked (non-swappable) memory, `sodium_memzero` for secure zeroing, and `sodium_memcmp` for constant-time comparison; all of these are required by the project requirements;
- it has a simple and well-documented API, reducing the risk of misuse compared with lower-level libraries such as OpenSSL;
- it is available in Debian's standard repositories and is cross-platform, facilitating build and reproducibility.

**libcjson** was chosen to read and write the configuration file and the JSON Lines log: it is a small, widely used parser available in Debian's repositories (`libcjson-dev`), and escaping all strings through a JSON library (instead of building JSON by hand) also prevents log and configuration injection through file names.

### Configuration File

The configuration file (`~/.config/sfm/sfm.config`) is a **JSON** file populated with the following fields:

- `kdf`: the key derivation function (`argon2id`);
- `salt`: the salt used for derivation (Base64, 16 bytes);
- `verifier`: the password verifier (Base64, 32 bytes);
- `vault`: the path to the vault;
- `log`: the path to the log file;
- `config`: the path to the configuration file itself (must match the location it was loaded from).

Example:

```json
{
	"kdf": "argon2id",
	"salt": "dGhpcyBpcyBhIHJhbmRvbSBzYWx0",
	"verifier": "a4f8...3b9e",
	"vault": "/home/username/.local/share/sfm/vault",
	"log": "/home/username/.local/state/sfm/sfm.log",
	"config": "/home/username/.config/sfm/sfm.config"
}
```

A configuration with a salt but no verifier (or the reverse) is rejected. The file is written atomically (temporary file, `fsync`, `rename`) with mode `0600`.

### Authentication

Login requires the master password: the entered password and the salt (read from the configuration file) are given to **Argon2id**, producing a 32-byte **master key**. A **verifier** is derived from the master key with HKDF-SHA256 (label `sfm-verifier-v1`) and compared, in **constant time**, with the verifier stored in the configuration file.

### Key Management

The chosen file-encryption scheme is **per-file DEK + KEK derived from the master key**:

- a **master key** is derived from the master password using Argon2id;
- a **Key-Encryption Key (KEK)** is derived from the master key with HKDF-SHA256 (label `sfm-kek-v1`, different from the verifier's label);
- for **each file** added to the vault, a random **Data-Encryption Key (DEK)** is generated and used to encrypt the file contents (libsodium `secretstream`, XChaCha20-Poly1305, in 128 KiB chunks so memory use is constant);
- the DEK is then encrypted ("wrapped") with the KEK (XChaCha20-Poly1305 AEAD, random nonce, the format magic and version authenticated as associated data), and the wrapped DEK (together with the nonce and tag) is stored in the 101-byte header of the encrypted file inside the vault;
- during decryption, the KEK (derived from the master key at login) is used to "unwrap" the DEK of the specific file, which in turn decrypts the contents.

Encrypted file layout: `"SFM1" | version (1 byte) | wrap nonce (24) | wrapped DEK (48) | stream header (24) | chunk 1 | ... | last chunk`. Every chunk carries a 17-byte tag and the last chunk is marked FINAL. The maximum file size is 256 GiB.

### File Handling

- **Symlinks are not followed**: only the original files can be added to the vault.
- Since the encryption operation involves removing the source file, the output is written to a temporary file, flushed with `fsync` and published atomically (`link`) only when complete; a failure halfway leaves the source untouched. The source is securely deleted only afterwards.
- When a file is encrypted and the source is deleted, its contents are **overwritten** with zeros, flushed, and then unlinked (secure delete, best-effort on SSDs and journaling or copy-on-write filesystems).

### Logging

The log is structured, and each line (JSON Lines format) records the following fields, as required by the project requirements:

- `event`: the name of the operation (`master_password_setup`, `login`, `list_files`, `file_encrypt`, `file_decrypt`, `file_delete`);
- `user`: the user/session identifier (for a local CLI: the effective `uid`, e.g., `uid=1000`);
- `timestamp`: the date and time of the event, in ISO 8601 format (UTC);
- `source`: the origin of the operation; for a local tool it is `local`, enriched with the terminal (`local:/dev/pts/0`) when available;
- `outcome`: `success` or `failure`;
- `target` (optional): the sanitized base name of the file involved, never a full path.

Every failed login attempt is recorded individually. Passwords, keys, tokens, or plaintext file contents are never logged. Any user input that ends up in the logs (file names) is reduced to its base name and sanitized before writing to prevent log injection. If the log file cannot be written, the failure is ignored so that a logging problem never exposes data or blocks access to the user's own files.

Example:

```log
{"timestamp":"2026-06-07T10:14:58Z","event":"login","user":"uid=1000","source":"local:/dev/pts/0","outcome":"failure"}
{"timestamp":"2026-06-07T10:15:00Z","event":"login","user":"uid=1000","source":"local:/dev/pts/0","outcome":"success"}
{"timestamp":"2026-06-07T10:15:10Z","event":"file_encrypt","user":"uid=1000","source":"local:/dev/pts/0","outcome":"success","target":"report.pdf"}
{"timestamp":"2026-06-07T10:15:12Z","event":"list_files","user":"uid=1000","source":"local:/dev/pts/0","outcome":"success"}
```
