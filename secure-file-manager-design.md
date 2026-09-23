# Secure File Encryption and Management System, Design Document

## Architecture

The program is designed as an **operating-system-level multi-user application**: each system user has an isolated and independent environment. Each user has their own vault and configuration files, while the executable is unique and installed at the system level, and is therefore shared by all users. This approach leverages the operating system's isolation and ownership mechanisms to prevent users other than the owner from accessing, reading, modifying, or deleting other users' files (with the exception of the system administrator).

### Program Startup

When the user runs the program, it checks for the existence of the configuration file, log file, and vault in the user's environment:

- **If the configuration file does not exist**, the program asks the user to create a master password for encrypting and decrypting files. The program then creates and populates the necessary files and directories. If the vault and/or log file already exist, execution is blocked.
- **If the vault and/or log file are missing but the configuration file exists**, the program recreates them according to the instructions contained in the configuration file.
- **If everything already exists**, the login page is displayed.

After initializing or recreating missing files, the program still displays the login page.

### Login

Login requires entering the master password:

- if the password is correct, the user gains access to the secure file storage;
- if the password is incorrect, the user is prompted to enter it again.

### Actions Available After Login

Once logged in, the user can perform the following actions:

- **list files**: lists all files present in the vault;
- **encrypt file**: adds a file to the vault;
- **decrypt file**: retrieves a file from the vault;
- **delete**: removes a file from the vault.

Only absolute paths are accepted and, before every file operation, ownership is verified: this means that the user can encrypt/decrypt only their own files and not those belonging to other users.

Once a file has been encrypted and placed in the vault, the original source file is removed. When a file is decrypted, a destination directory must be specified: the **decrypt operation copies the plaintext file to the specified destination, but keeps the encrypted copy in the vault** (it is not a destructive operation). The permanent removal of a file from the vault occurs only through the **delete** command, which securely deletes the encrypted file.

### Memory Management and Logging

After every encryption/decryption operation, the RAM used must be freed and overwritten to prevent a malicious user from reading its contents and extracting sensitive information. The same applies to the memory used when the user is prompted to enter the password.

Every major action must be recorded in the log file without exposing sensitive information. In case of problems, the program must terminate in a controlled manner ("crash gracefully"), reporting a generic error and without exposing sensitive information.

---

## Threat Model

The following table lists the main threats identified for the system, grouped by area, together with the planned mitigation.

### Authentication

| Threat                                                                        | Mitigation                                                                                                          |
| ----------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Brute-force attack on the master password                                    | Argon2id with a high cost factor; unlimited attempts with exponential backoff (e.g., delay 1s/2s/4s/...)           |
| Timing attack on verifier comparison                                          | Constant-time comparison (`sodium_memcmp`) instead of direct string comparison                                     |
| Password remaining in memory longer than necessary                           | The plaintext password is zeroed (`sodium_memzero`) immediately after deriving the master key                       |
| Denial of service through permanent account lockout after too many attempts  | The backoff is temporary, not a permanent lockout                                                                    |

### File Handling

| Threat                                                                      | Mitigation                                                                                                                           |
| --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| Path traversal (`..`, relative paths)                                       | Only absolute paths are accepted and are canonicalized before use                                                                   |
| Symlink attack (accessing files outside the vault through a symbolic link) | Symlinks are not followed (`O_NOFOLLOW`); only regular files are allowed                                                             |
| TOCTOU (race condition between checking and using the file)                | File opening followed by `fstat`/ownership verification on the file descriptor, not on the path                                     |
| A user accessing another user's files                                      | Ownership verification (`st_uid == geteuid()`) before every operation on files, config, vault, or log                             |
| Loss of the source file if encryption fails halfway through                | Write to a temporary file, `fsync`, atomic `rename` into the vault, and only then securely remove the source                       |
| Recovery of sensitive data from deleted files                               | Secure delete: overwrite the contents, `fsync`, then `unlink` (documented as best-effort on SSD/copy-on-write filesystems)         |
| Accidental overwriting of an existing vault during initialization          | If the vault exists but the config is missing, execution is blocked instead of reinitializing                                     |

### Key and Password Management

| Threat                                                                  | Mitigation                                                                                                                                                           |
| ----------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Exposure of the master key / DEK / KEK through a memory dump or swap    | Keys are kept in locked memory (`sodium_mlock`) and zeroed (`sodium_memzero`) as soon as they are no longer needed                                                   |
| Weak KDF for the master password                                        | Use of Argon2id (memory-hard) instead of simple hashes or checksums                                                                                                  |
| Compromise of a DEK exposing the entire vault                           | Each file has its own DEK, randomly generated and wrapped by the KEK: compromising one DEK does not expose the other files                                            |
| Process crash resulting in a core dump containing secrets               | Core dumps disabled (`setrlimit(RLIMIT_CORE, 0)`); signal handlers zero secrets before termination                                                                  |
| Secret leakage through logs                                             | Keys, the password, and file contents are never written to logs; logged fields are limited to event, user identifier, timestamp, source, and outcome                |

---

## Technical Details

The program will be written in **C23**, using **libsodium v1.0.18** as the cryptographic library, targeting **Debian 13** for execution.

The program runs as a **single CLI process** with the privileges of the user who invokes it. No `suid` or `root` privileges are required.

### Rationale for the Choices

**C23** was chosen because the course requires an explicit demonstration of secure memory management skills (secure allocation/deallocation, prevention of buffer overflows, use of safe string functions such as `strncpy`/`snprintf`): a low-level language such as C makes these mechanisms visible and verifiable, whereas a memory-safe language would hide them. Compared with previous versions of the standard, C23 provides useful improvements in this context (safer types, `nullptr`, improved compile-time checks), while still remaining a language that requires manual discipline in memory management.

**libsodium** was chosen as the cryptographic library because:

- it provides **audited** and actively maintained implementations of Argon2id, AEADs (AES-256-GCM, XChaCha20-Poly1305), and HKDF, avoiding the need to implement cryptographic primitives from scratch;
- it exposes primitives explicitly designed for secure memory and secret management: `sodium_malloc`/`sodium_mlock` for allocating locked (non-swappable) memory, `sodium_memzero` for secure zeroing, and `sodium_memcmp` for constant-time comparison; all of these are required by the project requirements;
- it has a simple and well-documented API, reducing the risk of misuse compared with lower-level libraries such as OpenSSL;
- it is available in Debian's standard repositories and is cross-platform, facilitating build and reproducibility.

### Configuration File

The configuration file is a **JSON** file populated with the following fields:

- `kdf`: the key derivation function (Argon2id);
- `salt`: the salt used for derivation;
- `verifier`: the password verifier;
- `vault`: the path to the vault;
- `log`: the path to the log file;
- `config`: the path to the configuration file itself.

Example:

```json
{
	"kdf": "argon2id",
	"salt": "dGhpcyBpcyBhIHJhbmRvbSBzYWx0",
	"verifier": "a4f8...3b9e",
	"vault": "/home/username/.local/share/sfm/vault/",
	"log": "/home/username/.local/state/sfm/sfm.log",
	"config": "/home/username/.config/sfm/sfm.config"
}
```

### Authentication

Login requires the master password: the entered password is applied to the salt (read from the configuration file), and the verifier is computed using the **Argon2id** algorithm. The result is compared, in **constant time**, with the verifier stored in the configuration file.

### Key Management

The chosen file-encryption scheme is **per-file DEK + KEK derived from the master key**:

- a **master key** is derived from the master password using Argon2id;
- a **Key-Encryption Key (KEK)** is derived from the master key, for example using HKDF;
- for **each file** added to the vault, a random **Data-Encryption Key (DEK)** is generated and used to encrypt the file contents (AEAD, e.g., AES-256-GCM or XChaCha20-Poly1305);
- the DEK is then encrypted ("wrapped") with the KEK, and the encrypted DEK (together with the nonce and tag) is stored in the header of the encrypted file inside the vault;
- during decryption, the KEK (derived from the master key at login) is used to "unwrap" the DEK of the specific file, which in turn decrypts the contents.

### File Handling

- **Symlinks are not followed**: only the original files can be added to the vault.
- Since the encryption operation involves removing the source file, the operation must be **atomic**: otherwise, a failure halfway through could cause the loss of the source file.
- When a file is encrypted and the source is deleted, the memory/disk space occupied by the original file must be **erased and overwritten** (secure delete).

### Logging

The log is structured, and each line (JSON Lines format) records the following fields, as required by the project requirements:

- `event`: the name of the operation (e.g., `file_encrypt`, `file_decrypt`, `file_delete`, `list_files`, `login`);
- `user`: the user/session identifier (for a local CLI: the process `uid`, e.g., `uid=1000`);
- `timestamp`: the date and time of the event, in ISO 8601 format;
- `source`: the origin of the operation; for a local tool it is always `local`, optionally enriched with `hostname`/`tty`;
- `outcome`: `success` or `failure`.

Passwords, keys, tokens, or plaintext file contents are never logged. Any user input that ends up in the logs (e.g., file names) is sanitized before writing to prevent log injection.

Example:

```log
{"timestamp":"2026-06-07T10:15:00Z","event":"file_encrypt","user":"uid=1000","source":"local","outcome":"success"}
{"timestamp":"2026-06-07T10:15:01Z","event":"list_files","user":"uid=1000","source":"local","outcome":"failure"}
{"timestamp":"2026-06-07T10:15:02Z","event":"file_decrypt","user":"uid=1000","source":"local","outcome":"success"}
```
