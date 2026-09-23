# Secure File Manager (sfm)

## Scope

`sfm` is a command-line tool for the secure management of encrypted files, developed for the ICS0022 Secure Programming course (Project 1: Secure File Encryption and Management System).

The program allows each system user to maintain a personal and isolated **vault** in which they can securely encrypt, decrypt, and delete their own files, protecting access through a master password and the operating system's ownership mechanisms. The executable is intended to be installed only once at the system level and shared by all users, each with their own isolated environment (config, vault, log).

## Available Commands

| Command                                                           | Description                                                                                              |
| ----------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `list`                                                            | Lists the files present in the user's vault                                                              |
| `encrypt <absolute-path>`                                         | Encrypts the specified file and places it in the vault; the original source is securely removed        |
| `decrypt <file-name-in-vault> <absolute-destination-directory>`  | Copies the decrypted file from the vault to the specified destination; the encrypted copy remains in the vault |
| `delete <file-name-in-vault>`                                     | Securely deletes (secure delete) a file from the vault                                                   |

On the first run, if the configuration file does not exist, the program guides the user through creating the master password and initializing the config, vault, and log. On subsequent runs, the program requests the master password for access.

## Build

Requirements:

- Debian 13 (or compatible)
- C23-compliant compiler (e.g., GCC 14+ or recent Clang)
- libsodium v1.0.18 (headers and development library)

```bash
sudo apt install libsodium-dev
```

## Run

```bash
./sfm
sfm> command <argument>
```

Example:

```bash
sfm> encrypt /home/username/documents/report.pdf
sfm> list
sfm> decrypt report.pdf.enc /home/username/desktop/
sfm> delete report.pdf.enc
```

## Project Status

Repository in the early development phase — Checkpoint 1 (threat model and architecture). See `secure-file-manager-design.md` for the complete design document, threat model, and technical details.
