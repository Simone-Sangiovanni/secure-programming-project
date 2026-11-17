The C23 codebase implements the core security architecture described in `secure-file-manager-design.md`—including Argon2id with domain separation, per-file DEKs wrapped by a KEK under XChaCha20-Poly1305, descriptor-level ownership checks, `O_NOFOLLOW`, atomic file creation, and structured JSON Lines audit logging—but there are **several mismatches between the code, the architecture diagram, and the design document**, as well as **outdated documentation and missing Checkpoint 3 deliverables**.
## 1. Does the Code Respect the Design?

The implementation is strong and well-hardened, particularly in `CMakeLists.txt` (C23, Full RELRO, PIE, stack clash protection, CET, ASan/UBSan) and `fileio.c`/`init.c` (`openat`/`mkdirat` traversal and `fstat` UID checks). However, a reviewer comparing the code against `architecture.jpeg` and `secure-file-manager-design.md` will find the following discrepancies:

|**Area**|**Design (architecture.jpeg & secure-file-manager-design.md)**|**Actual Code (src/*.c)**|
|---|---|---|
|**Language & Diagram Layout**|`architecture.jpeg` labels the process `SFM Process (python)` and stores files under `~/.sfm/` (`users.db`, `index.enc`, `blobs/*.bin`, `sfm.log`).|Implemented in **C23** using XDG paths (`~/.config/sfm/config.json`, `~/.local/state/sfm/sfm.log`, and `~/.local/share/sfm/vault/*.sfm`) with no database or encrypted index file.|
|**Locked Memory (`sodium_mlock`)**|States that keys are kept in locked memory (`sodium_mlock` / `sodium_malloc`) so they cannot be swapped to disk.|Neither `sodium_mlock()` nor `sodium_malloc()` is used anywhere; keys and passwords live on the standard stack or regular `malloc` heap (though they are wiped with `sodium_memzero()`).|
|**Post-Setup Login Flow**|States that after first-run initialization, the program still displays the login page.|`authenticate()` in `main.c` logs the user straight into the shell immediately after `auth_setup_master_password()` succeeds.|
|**Recreating Missing Vault/Log**|States that if `config.json` exists but the vault or log is missing, they are recreated using the paths inside `config.json`.|`init_setup()` creates hardcoded XDG paths _before_ `load_config()` parses `config.json`, ignoring custom `vault` or `log` paths configured in the JSON.|
|**Signal Handling**|Claims signal handlers zero secrets before termination.|`cli_ignore_signals()` ignores `SIGINT`, `SIGQUIT`, and `SIGTSTP` via `SIG_IGN`; no signal handler wipes secrets on termination signals such as `SIGTERM`.|
|**Config Schema & Filename**|Shows `sfm.config` with 6 JSON keys (`kdf`, `salt`, `verifier`, `vault`, `log`, `config`).|Uses `config.json` and `save_config()` writes 5 keys, omitting `"config"`.|
|**KDF Primitive**|Mentions deriving the KEK from the master key _"for example using HKDF"_.|Uses libsodium's BLAKE2b-based `crypto_kdf_derive_from_key()`, which is sound and idiomatic for libsodium but differs slightly from the text.|

## 2. Does the Project Respect the Checkpoints?

- **Checkpoint 1 — Threat model and architecture (Week 4): Mostly satisfied, needs diagram update**
    - `secure-file-manager-design.md` thoroughly covers the threat model (authentication, file handling, key/password management) and justifies C23 and libsodium (though `libcjson` from `CMakeLists.txt` should also be listed there).
    - `architecture.jpeg` is an outdated early draft (`python`, `~/.sfm/users.db`, `blobs/*.bin`, and wrong module execution order) that no longer reflects the C23 design or implementation.  
- **Checkpoint 2 — Core requirements implemented (Week 9): Code satisfies it, `README.md` is broken**
    - The C codebase fulfills all Checkpoint 2 functional requirements (CLI, encryption/decryption, Argon2id authentication, and initial path validation).
    - However, `README.md` is severely out of date and contains inaccurate build/run instructions:
        - It still states _"Repository in the second development phase — Checkpoint 2"_, claims _"`list` and `secure_delete` are not implemented yet"_, and says _"Currently there is no vault"_, even though all of those features are fully implemented in `commands.c`
        - It instructs the user to run `./basic_setup.sh` (which does not exist; `init.c` handles setup automatically) and `./sfm` (instead of `./build/sfm`).
        - Its usage example `sfm> decrypt "report.pdf.sfm"` omits the required `<absolute_destination_directory>` argument.
    - Because no `.git` folder was included in the archive, ensure your repository history has at least one commit per working session as required.
- **Checkpoint 3 — Near-final state (Week 12): Code nearly complete, missing test suite and report**
    - **Completed in code:** Secure string handling (`snprintf`), zeroing (`sodium_memzero`), path canonicalization (`realpath`), symlink protection (`O_NOFOLLOW`), structured JSON Lines logging (`log.c`), generic error strings without `errno`/stack leaks, and per-user UID enforcement (`st.st_uid == geteuid()`).
    - **Incomplete / Missing:**
        - `sodium_mlock` / `sodium_malloc` is missing despite being promised in the design doc.
        - **Test suite is missing:** No automated or documented test cases exist yet covering encryption/decryption round-trips, tampering/truncation detection, secure deletion, wrong-password backoff, ownership failures, or path-traversal edge cases.
        - **Draft report is missing:** Only `secure-file-manager-design.md` is present; the full report (Introduction, Implementation, Security Analysis, Conclusion) and user manual required by Sections 3.3 and 3.4.3 are not included.
## 3. Recommended Fixes Before Submission

1. **Rewrite `README.md`:** Update the project status, remove the false notes about `list`, `secure_delete`, and the vault not being implemented, fix the executable path (`./build/sfm`), remove `./basic_setup.sh`, and fix the `decrypt` example to include the destination directory.
2. **Redraw `architecture.jpeg`:** Update it to reflect C23, `libsodium` + `libcjson`, the real startup order (`init -> config -> auth -> cli -> validate -> commands -> filecrypt -> cipher/fileio`), and the actual XDG paths (`~/.config/sfm/config.json`, `~/.local/share/sfm/vault/*.sfm`, `~/.local/state/sfm/sfm.log`).
3. **Align `sodium_mlock` and Design Details:** Either add `sodium_mlock()`/`sodium_munlock()` around `key` in `main.c` and `master`/`dek` in `auth.c`/`cipher.c` (plus mention `libcjson` in `secure-file-manager-design.md`), or update `secure-file-manager-design.md` so the design document accurately matches what the code actually does.
4. **Clean Up Minor Code Edge Cases:** Remove the unused `CMD_ERR_NOT_IMPLEMENTED` enum value in `commands.h`/`commands.c`, and sanitize control characters in filenames printed to `stderr` in `cmd_decrypt()` and `cmd_secure_delete()` (matching `print_sanitized_name()` in `cmd_list()`).
5. **Add Tests and the Report:** Add a `tests/` directory (e.g., via CTest or a shell/C test harness) covering all Checkpoint 3 test scenarios, and write the final report and user manual.