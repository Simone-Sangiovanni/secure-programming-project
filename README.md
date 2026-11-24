# Secure File Manager (sfm)

## Scope

`sfm` is a command-line tool for the secure management of encrypted files, developed for the ICS0022 Secure Programming course (Project 1: Secure File Encryption and Management System).

The program allows each system user to maintain a personal and isolated **vault** in which they can securely encrypt, decrypt, and delete their own files, protecting access through a master password and the operating system's ownership mechanisms. The executable is intended to be installed once at the system level and shared by all users, each with their own isolated environment (config, vault, log). `sfm` refuses to run as root.

## Commands

Start the program, log in with your master password, then use the `sfm>` shell:

| Command | Description |
| - | - |
| `list` | Lists the encrypted files (`*.sfm`) in the user's vault |
| `encrypt <absolute-path>` | Encrypts the file and places it in the vault as `<name>.sfm`; the original is securely deleted afterwards |
| `decrypt <file-name-in-vault> <absolute-destination-directory>` | Writes the decrypted file to the destination directory; the encrypted copy stays in the vault; existing files are never overwritten |
| `secure_delete <file-name-in-vault \| absolute-path>` | Securely deletes (overwrite, then unlink) a file: a vault file by name, or any regular file you own anywhere else by absolute path |
| `help` | Shows the commands |
| `exit` | Quits the program |

Use double quotes around paths that contain spaces. Command-line options: `-h` (help), `-v` (version).

On the first run the program guides you through creating the master password (8-64 characters with an uppercase letter, a lowercase letter, a digit and a special character) and creates the configuration, vault and log automatically; you then log in with the new password. On later runs it asks for the master password. Wrong passwords are logged and slow down further attempts (1 s, 2 s, 4 s ... up to 30 s) but never lock the account.

Files used (all per user, folders `0700`, files `0600`):

| File | Location |
| - | - |
| Configuration | `~/.config/sfm/sfm.config` |
| Vault | `~/.local/share/sfm/vault/` |
| Log (JSON Lines) | `~/.local/state/sfm/sfm.log` |

## Prerequisites & Dependencies (Debian 13)

- **GCC** 14.2 (C23 support required by `CMakeLists.txt`)
- **CMake** >= 3.21 (Debian 13 provides 3.31)
- **Ninja**, **pkg-config**
- **libsodium-dev** (cryptography) and **libcjson-dev** (JSON)
- **Python 3** (only to run the end-to-end test)

```bash
sudo apt update
sudo apt install build-essential gcc cmake ninja-build pkg-config libsodium-dev libcjson-dev python3
```

## Build

```bash
cmake -B build -G Ninja
cmake --build build
```

The default build type is `Debug`, which enables ASan/UBSan. For an optimized, hardened build use `cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release`.

## Run

No manual setup is needed: `sfm` creates its folders and files on first start.

```bash
./build/sfm
sfm> encrypt "/home/username/documents/report.pdf"
sfm> list
sfm> decrypt "report.pdf.sfm" "/home/username/restored"
sfm> secure_delete "report.pdf.sfm"
sfm> secure_delete "/home/username/old_notes.txt"
sfm> exit
```

Optional system-wide installation, shared by all users (installs to `/usr/local/bin`):

```bash
sudo cmake --install build
sfm
```

## Tests

`tests/test_sfm.py` is an end-to-end test written in Python: it starts the real `sfm` in a pseudo-terminal, types the passwords and commands like a user, and checks what happens. Run it as a **normal user** (sfm refuses to run as root):

```bash
python3 tests/test_sfm.py build/sfm              # everything (about 1 minute)
python3 tests/test_sfm.py build/sfm --only commands   # init, access, commands or behavior
ctest --test-dir build --output-on-failure -V    # the same test through CTest
```

It follows the test specification, section by section, and prints one PASS/FAIL line per question:

| Section | What is verified |
| - | - |
| 1. Initialization | A very simple, empty and very long master password are refused; 13 passwords with special characters (format specifiers, `$()`, backticks, SQL, quotes, UTF-8, escape codes, random) neither break nor are interpreted by the program; a 64-character password is accepted; `MasterPSW1!` registers; permissions and configuration format |
| 2. Access | The same bad inputs at the login; brute-force resistance (the delay doubles 1, 2, 4, 8 s, each guess costs an Argon2id computation, failures are logged, no permanent lock-out) |
| 3. Commands | **encrypt**: ciphertext in the vault, source wiped on disk and in RAM, relative/`..`/symlinked paths, symlink refused, too-long paths and names refused, other users' files refused, name collision with a vault file refused. **decrypt**: file placed in the destination, vault copy kept, destination resolved, too-long paths refused, existing destination file not overwritten. **secure_delete**: inside and outside the vault, blocks zeroed, no trace in RAM, other users' files refused. **exit**: clean status, terminal restored, `SIGTERM` handled, core dumps disabled |
| 4. Behavior | Passwords are not left in RAM; the log contains no secret and is valid JSON; the program survives (or safely refuses) deleted, corrupted, re-permissioned or link-replaced config, vault and log, and modified vault files |

How "no trace" is checked: **disk** - a second hard link to the file is created first, so after the command the old blocks can still be read and must be all zeros; **RAM** - the memory of the running `sfm` process (`/proc/<pid>/mem`) is searched for the plaintext and the passwords, after a positive control proves the scanner can find a string known to be there. The RAM checks are skipped (not failed) if the system forbids reading the process memory. The `mlock` check needs the Release build (`-DCMAKE_BUILD_TYPE=Release`); sanitizer builds do not report locked pages.

All tests run with a private `$HOME` in temporary folders; your real vault is never touched. Add `--keep` to keep those folders for debugging.

## Resetting (development only)

```bash
./reset.sh
```

**Warning:** this permanently deletes your sfm configuration, **vault and log** without asking. Encrypted files cannot be recovered afterwards.

## Project Status

Final implementation phase (Checkpoint 3): all commands are implemented and covered by the end-to-end test. See `secure-file-manager-design.md` for the design document, threat model and technical details, `architecture.jpg` for the architecture diagram, and `report-draft.md` for the draft report.

## Known limitations

- Secure delete overwrites the file once with zeros; on SSDs and journaling or copy-on-write filesystems this is best-effort only.
- The login backoff is per process; restarting the program resets it.
- `SIGINT`, `SIGQUIT` and `SIGTSTP` are ignored, so a long operation can only be stopped with `SIGTERM`.
- Files are limited to 256 GiB.
