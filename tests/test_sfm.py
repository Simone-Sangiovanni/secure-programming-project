#!/usr/bin/env python3
"""
End-to-end test of the sfm (Secure File Manager) C program.

    python3 tests/test_sfm.py /path/to/build/sfm [--only init,access,commands,behavior] [--keep]

The program under test is started for real, inside a pseudo-terminal, exactly
like a user would run it: this script types the passwords and the commands and
reads what sfm prints. Nothing of sfm is mocked.

The tests follow the questions of the test specification, in the same order:

    1. INITIALIZATION  master password registration (simple / very long / special characters / valid)
    2. ACCESS          login with the same inputs, and resistance to brute force
    3. COMMANDS        encrypt, decrypt, secure_delete, exit
    4. BEHAVIOR        passwords in RAM, secrets in the log, tampered config/vault/log

How the "no trace" questions are answered
  * Disk : before a file is encrypted/deleted, a second hard link to the same
           inode is created. After the command the original name is gone, but the
           hard link still reaches the old blocks, so we can read them and verify
           they were overwritten with zeros. The whole test area is also searched
           for the plaintext.
  * RAM  : the memory of the running sfm process (/proc/<pid>/mem) is searched
           for the plaintext / the passwords. A "positive control" first checks
           that the scanner really can find a string that is known to be in the
           process, so a clean result means something.

Everything runs in throw-away directories with a private $HOME, so your real
vault, config and log are never touched. sfm refuses to run as root, so run
this as a normal user. Exit status: 0 = all passed, 1 = something failed,
77 = skipped (root).
"""
import argparse
import atexit
import json
import os
import pty
import random
import select
import shutil
import signal
import stat
import string
import sys
import tempfile
import termios
import time

PROMPT = "sfm> "
GOOD_PW = "MasterPSW1!"           # the valid master password used by the specification
WRONG_PW = "WrongPSW1!"           # well-formed, but not the master password
CHUNK = 128 * 1024                # sfm encrypts in 128 KiB chunks

# Passwords that might break a careless program. Every one of them satisfies the
# password policy (upper, lower, digit, special; 8-64 chars), so they are valid.
SPECIAL_PASSWORDS = [
    ("printf format specifiers", "P@ss%s%s%n%x%x-w0rd!"),
    ("shell command substitution", "$(touch PWNED)Aa1!;"),
    ("backticks and pipes", "`touch PWNED`Aa1!|&"),
    ("SQL-injection style", "';DROP TABLE users;--Aa1"),
    ("quotes and backslashes", '"quoted\\"AND\\\\back1!'),
    ("JSON-like", '{"a":"B1c!"}'),
    ("UTF-8 characters", "Ünïcödé-Pässwörd-1!"),
    ("terminal escape codes", "\x1b[31mAa1!\x1b[0m"),
    ("path-like with spaces", "../../etc/passwd Aa1!"),
    ("tab character", "Aa1! tab\there"),
]
_rng = random.Random(20260101)  # fixed seed: the "random" passwords are reproducible
for _i in range(3):
    _pool = string.ascii_letters + string.digits + string.punctuation
    _pw = "".join(_rng.choice(_pool) for _ in range(24)) + "Aa1!"
    SPECIAL_PASSWORDS.append((f"random characters #{_i + 1}", _pw))


# ======================================================================
#  Tiny reporting framework
# ======================================================================
class Report:
    def __init__(self):
        self.passed = self.failed = self.skipped = 0
        self.failures = []

    def section(self, title):
        print(f"\n{'=' * 72}\n{title}\n{'=' * 72}")

    def sub(self, title):
        print(f"\n--- {title}")

    def check(self, ok, text, detail=""):
        if ok:
            self.passed += 1
            print(f"  [PASS] {text}")
        else:
            self.failed += 1
            self.failures.append(text)
            print(f"  [FAIL] {text}")
            if detail:
                print("         " + str(detail).strip().replace("\n", "\n         ")[:600])

    def info(self, text):
        print(f"  [INFO] {text}")

    def skip(self, text):
        self.skipped += 1
        print(f"  [SKIP] {text}")


R = Report()
check, info, skip = R.check, R.info, R.skip


class FlowError(Exception):
    """The program did not behave as the scenario needs (timeout, unexpected exit)."""


def scenario(title):
    """Decorator: runs a test function and turns a FlowError into one clear FAIL."""
    def wrap(fn):
        def run(*args, **kwargs):
            R.sub(title)
            try:
                return fn(*args, **kwargs)
            except FlowError as e:
                check(False, f"scenario could not complete: {title}", str(e))
        return run
    return wrap


# ======================================================================
#  A throw-away user environment and a running sfm
# ======================================================================
KEEP = False
BOXES = []
SESSIONS = []


class Box:
    """A private $HOME plus a work and a destination folder."""

    def __init__(self, exe, tag):
        self.exe = exe
        self.root = os.path.realpath(tempfile.mkdtemp(prefix=f"sfm-e2e-{tag}-"))
        os.chmod(self.root, 0o700)
        self.home = self._mk("home")
        self.work = self._mk("work")
        self.dest = self._mk("dest")
        self.config = f"{self.home}/.config/sfm/sfm.config"
        self.vault = f"{self.home}/.local/share/sfm/vault"
        self.log = f"{self.home}/.local/state/sfm/sfm.log"
        BOXES.append(self)

    def _mk(self, name):
        p = os.path.join(self.root, name)
        os.mkdir(p, 0o700)
        return p

    def write(self, directory, name, data):
        path = os.path.join(directory, name)
        with open(path, "wb") as f:
            f.write(data)
        return path

    def vault_files(self):
        return sorted(os.listdir(self.vault)) if os.path.isdir(self.vault) else []

    def read_config(self):
        with open(self.config) as f:
            return json.load(f)

    def has_credentials(self):
        try:
            cfg = self.read_config()
            return bool(cfg.get("salt")) and bool(cfg.get("verifier"))
        except (OSError, ValueError):
            return False

    def snapshot(self):
        """Copy $HOME so a tampering scenario can be undone."""
        snap = self.home + ".snapshot"
        shutil.rmtree(snap, ignore_errors=True)
        shutil.copytree(self.home, snap, symlinks=True)

    def restore(self):
        subprocess_chmod_tree(self.home)
        shutil.rmtree(self.home, ignore_errors=True)
        shutil.copytree(self.home + ".snapshot", self.home, symlinks=True)

    def cleanup(self):
        subprocess_chmod_tree(self.root)
        shutil.rmtree(self.root, ignore_errors=True)


def subprocess_chmod_tree(path):
    """Tests change permissions to 000 on purpose; make everything removable again."""
    for dirpath, dirnames, filenames in os.walk(path):
        for n in dirnames + filenames:
            p = os.path.join(dirpath, n)
            if not os.path.islink(p):
                try:
                    os.chmod(p, 0o700)
                except OSError:
                    pass
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass


class Sfm:
    """One running sfm process attached to a pseudo-terminal (the 'user at the keyboard')."""

    def __init__(self, box):
        self.box = box
        env = {"HOME": box.home, "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
               "ASAN_OPTIONS": "detect_leaks=0"}
        self.pid, self.fd = pty.fork()
        if self.pid == 0:                        # child: become sfm
            os.chdir(box.work)
            os.execve(box.exe, [box.exe], env)
        self.buf = ""            # output not consumed by expect() yet
        self.before = ""         # output consumed by the last expect()
        self.transcript = ""     # everything sfm ever printed
        self.eof = False
        self.code = None
        self.expected_signal = False
        SESSIONS.append(self)

    # ---- talking to the program ----
    def _pump(self, timeout):
        r, _, _ = select.select([self.fd], [], [], timeout)
        if not r:
            return False
        try:
            data = os.read(self.fd, 65536)
        except OSError:
            data = b""
        if not data:
            self.eof = True
            return False
        text = data.decode("utf-8", "replace").replace("\r", "")
        self.buf += text
        self.transcript += text
        return True

    def expect(self, text, timeout=40):
        end = time.monotonic() + timeout
        while text not in self.buf:
            if self.eof:
                raise FlowError(f"sfm ended while waiting for {text!r}; it printed: {self.buf[-300:]!r}")
            if time.monotonic() > end:
                raise FlowError(f"timeout waiting for {text!r}; got: {self.buf[-300:]!r}")
            self._pump(0.2)
        self.before, self.buf = self.buf.split(text, 1)
        return self.before

    def send_line(self, text):
        os.write(self.fd, (text + "\n").encode("utf-8"))

    def send_eof(self):
        os.write(self.fd, b"\x04")           # Ctrl-D

    def run(self, command, timeout=60):
        """Type a shell command and return what sfm printed before the next prompt."""
        self.buf = ""
        self.send_line(command)
        out = self.expect(PROMPT, timeout)
        return out.split("\n", 1)[1] if "\n" in out else ""   # drop the echoed command

    def wait(self, timeout=40):
        """Wait for the process to end; returns its exit status (128+N if killed by signal N)."""
        end = time.monotonic() + timeout
        while self.code is None:
            self._pump(0.1)
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                while self._pump(0.1):
                    pass
                self.code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128 + os.WTERMSIG(status)
            elif time.monotonic() > end:
                os.kill(self.pid, signal.SIGKILL)
                os.waitpid(self.pid, 0)
                self.code = -1
                raise FlowError("sfm did not terminate in time")
        return self.code

    def alive(self):
        if self.code is not None:
            return False
        pid, status = os.waitpid(self.pid, os.WNOHANG)
        if pid:
            self.code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128 + os.WTERMSIG(status)
            return False
        return True

    def close(self):
        if self.code is None and self.alive():
            self.expected_signal = True
            os.kill(self.pid, signal.SIGKILL)
            os.waitpid(self.pid, 0)
            self.code = -9

    # ---- looking at the process from outside ----
    def echo_enabled(self):
        return bool(termios.tcgetattr(self.fd)[3] & termios.ECHO)

    def proc_status(self, field):
        with open(f"/proc/{self.pid}/status") as f:
            for line in f:
                if line.startswith(field + ":"):
                    return line.split(":", 1)[1].strip()
        return ""

    def core_limit(self):
        with open(f"/proc/{self.pid}/limits") as f:
            for line in f:
                if line.startswith("Max core file size"):
                    return line.split()[4:6]
        return None

    def scan_memory(self, needles):
        """Count occurrences of each byte string in this process's writable/anonymous memory."""
        needles = [n if isinstance(n, bytes) else n.encode() for n in needles]
        hits = {n: 0 for n in needles}
        overlap = max(len(n) for n in needles) - 1
        with open(f"/proc/{self.pid}/maps") as maps, open(f"/proc/{self.pid}/mem", "rb", 0) as mem:
            for line in maps:
                parts = line.split(None, 5)
                rng, perms = parts[0], parts[1]
                path = parts[5].strip() if len(parts) > 5 else ""
                if "r" not in perms or "p" not in perms:
                    continue
                if path.startswith("/") or path in ("[vvar]", "[vsyscall]", "[vdso]"):
                    continue                      # program/library files, not data
                start, end = (int(x, 16) for x in rng.split("-"))
                if end - start > (1 << 30):
                    continue                      # huge reserved ranges (sanitizer shadow memory)
                pos, tail = start, b""
                while pos < end:
                    size = min(4 << 20, end - pos)
                    try:
                        mem.seek(pos)
                        data = mem.read(size)
                    except (OSError, ValueError, OverflowError):
                        break
                    if not data:
                        break
                    window = tail + data
                    for n in needles:
                        hits[n] += window.count(n)
                    tail = window[-overlap:] if overlap > 0 else b""
                    pos += size
        return hits


@atexit.register
def _cleanup():
    for s in SESSIONS:
        try:
            s.close()
        except Exception:
            pass
    if not KEEP:
        for b in BOXES:
            try:
                b.cleanup()
            except Exception:
                pass


# ---- common ways of starting the program ----
def register(box, pw=GOOD_PW):
    """First run: choose and confirm the master password, then log in. Returns a session at the shell."""
    s = Sfm(box)
    s.expect("Choose a master password: ")
    s.send_line(pw)
    s.expect("Confirm master password: ")
    s.send_line(pw)
    s.expect("Please log in to continue.", 60)
    s.expect("Master password: ")
    s.send_line(pw)
    s.expect("Authenticated.", 60)
    s.expect(PROMPT)
    return s


def login(box, pw=GOOD_PW):
    """Normal start: log in with the master password. Returns a session at the shell."""
    s = Sfm(box)
    s.expect("Master password: ")
    s.send_line(pw)
    s.expect("Authenticated.", 60)
    s.expect(PROMPT)
    return s


def end(s):
    """Leave the shell with the exit command and return the exit status."""
    s.send_line("exit")
    return s.wait()


def registered_box(exe, tag, pw=GOOD_PW):
    box = Box(exe, tag)
    s = register(box, pw)
    end(s)
    return box


def q(path):
    return f'"{path}"'


def make_content(label):
    """~300 KB (3 encryption chunks) of text that contains a unique marker."""
    marker = f"PLAINTEXT-{label}-{random.SystemRandom().getrandbits(64):016x}".encode()
    return marker, (marker + b"\n") * (300_000 // (len(marker) + 1))


def files_containing(root, needle):
    found = []
    for dirpath, _, filenames in os.walk(root):
        for n in filenames:
            p = os.path.join(dirpath, n)
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            try:
                with open(p, "rb") as f:
                    if needle in f.read():
                        found.append(p)
            except OSError:
                pass
    return found


def leftovers(*dirs):
    """Temporary files sfm may leave behind when something fails halfway."""
    return [os.path.join(d, n) for d in dirs if os.path.isdir(d) for n in os.listdir(d) if n.startswith(".sfm-tmp-")]


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def memory_scanner_works(s):
    """Positive control: type a unique string; it must be found in the process memory."""
    control = f"memory-control-{random.SystemRandom().getrandbits(48):012x}"
    s.run(control)
    try:
        return s.scan_memory([control])[control.encode()] > 0
    except OSError as e:
        info(f"cannot read the process memory ({e}); RAM checks are skipped")
        return False


def crashed(text):
    return any(w in text for w in ("Sanitizer", "runtime error", "Segmentation", "core dumped", "stack smashing"))


# ======================================================================
#  1. INITIALIZATION
# ======================================================================
def test_initialization(exe):
    R.section("1. INITIALIZATION: registering the master password")

    @scenario("A very simple password must be refused")
    def simple():
        for label, pw, expected in [
            ("'abc' (too short and too simple)", "abc", "8-64"),
            ("'password' (lowercase only)", "password", "8-64"),
            ("'12345678' (digits only)", "12345678", "8-64"),
            ("'Password1' (no special character)", "Password1", "8-64"),
            ("empty password", "", "empty"),
        ]:
            box = Box(exe, "init")
            s = Sfm(box)
            s.expect("Choose a master password: ")
            s.send_line(pw)
            code = s.wait()
            check(code != 0 and expected in s.transcript, f"{label} is refused", s.transcript)
            check(not box.has_credentials(), "  nothing was stored in the configuration")
            check(not crashed(s.transcript), "  the program did not crash")
    simple()

    @scenario("A very long password must be refused")
    def long_pw():
        for n in (65, 200, 1000):
            box = Box(exe, "init")
            s = Sfm(box)
            s.expect("Choose a master password: ")
            s.send_line("Aa1!" + "x" * (n - 4))
            code = s.wait()
            check(code != 0 and "too long" in s.transcript.lower(), f"{n}-character password is refused", s.transcript)
            check(not box.has_credentials() and not crashed(s.transcript), "  nothing stored, no crash")
    long_pw()

    @scenario("Passwords with special characters must not break the program")
    def special():
        for label, pw in SPECIAL_PASSWORDS:
            box = Box(exe, "special")
            s = register(box, pw)                      # registers and logs in with it
            code = end(s)
            s2 = login(box, pw)                        # and again in a new run
            end(s2)
            stray = [p for p in (f"{box.work}/PWNED", f"{box.home}/PWNED", "PWNED") if os.path.exists(p)]
            ok = (code == 0 and not crashed(s.transcript + s2.transcript) and box.has_credentials() and not stray)
            check(ok, f"{label}: registers, logs in, exits cleanly; nothing is interpreted or broken",
                  [s.transcript[-200:], stray])
        box = Box(exe, "boundary")
        s = register(box, "Aa1!" + "y" * 60)
        check(True, "a password of exactly 64 characters (the maximum) is accepted")
        end(s)
    special()

    @scenario("Mismatching confirmation must be refused")
    def mismatch():
        box = Box(exe, "init")
        s = Sfm(box)
        s.expect("Choose a master password: ")
        s.send_line(GOOD_PW)
        s.expect("Confirm master password: ")
        s.send_line(GOOD_PW + "x")
        code = s.wait()
        check(code != 0 and "do not match" in s.transcript and not box.has_credentials(),
              "different confirmation is refused", s.transcript)
    mismatch()

    @scenario(f"A valid master password ({GOOD_PW!r}) must register")
    def valid():
        box = Box(exe, "valid")
        s = register(box)
        check(True, f"{GOOD_PW!r} is accepted and the user can log in right after")
        check(end(s) == 0, "the program exits cleanly")
        cfg = box.read_config()
        check(set(cfg) == {"kdf", "salt", "verifier", "vault", "log", "config"} and cfg["kdf"] == "argon2id",
              "configuration holds the 6 documented fields (argon2id)", cfg)
        check(mode(box.config) == 0o600 and mode(os.path.dirname(box.config)) == 0o700,
              "configuration file is 0600 and its folder 0700")
        check(mode(box.vault) == 0o700 and mode(box.log) == 0o600, "vault folder is 0700 and the log is 0600")
        check(GOOD_PW not in open(box.config).read(), "the password itself is not stored in the configuration")
    valid()


# ======================================================================
#  2. ACCESS
# ======================================================================
def test_access(exe):
    R.section("2. ACCESS: login and brute-force resistance")
    box = registered_box(exe, "access")

    @scenario("Login must survive the same bad inputs (simple / long / special characters)")
    def bad_inputs():
        for label, pw in [("a very simple password", "abc"), ("an empty password", ""),
                          ("an SQL-style password", "' OR '1'='1")] + \
                         [(f"special characters ({n})", p) for n, p in SPECIAL_PASSWORDS[:3] + SPECIAL_PASSWORDS[6:8]]:
            s = Sfm(box)
            s.expect("Master password: ")
            s.send_line(pw)
            s.expect("Wrong password", 40)
            s.expect("Master password: ", 20)
            s.send_eof()
            code = s.wait()
            check("Authenticated" not in s.transcript and code != 0 and not crashed(s.transcript),
                  f"{label}: refused as a wrong password, no crash", s.transcript)
        s = Sfm(box)
        s.expect("Master password: ")
        s.send_line("Aa1!" + "x" * 196)
        code = s.wait()
        check(code != 0 and "too long" in s.transcript.lower() and "Authenticated" not in s.transcript,
              "a 200-character password is refused (too long), no crash", s.transcript)
        check(not os.path.exists(f"{box.work}/PWNED"), "no special character was executed")
        s = login(box)
        check(True, "after all those failures the correct password still works (no lock-out)")
        end(s)
    bad_inputs()

    @scenario("Login must resist brute force: the delay grows after every wrong guess")
    def brute_force():
        s = Sfm(box)
        s.expect("Master password: ")
        delays = []
        for i in range(4):
            t0 = time.monotonic()
            s.send_line(f"Guess{i}!Wrong")
            s.expect("Wrong password", 40)
            t_kdf = time.monotonic() - t0
            waiting = s.expect("before next attempt", 20)
            s.expect("Master password: ", 40)
            delays.append((time.monotonic() - t0, t_kdf, waiting.strip()))
            if i == 0:
                info(f"one guess costs {t_kdf:.2f} s of Argon2id (memory-hard) before any delay")
                check(t_kdf > 0.1, "each guess has a real computational cost (Argon2id)")
        for i, (total, _, msg) in enumerate(delays):
            want = 2 ** i
            check(total >= want, f"after wrong guess #{i + 1} sfm waits at least {want} s (waited {total:.1f} s)", msg)
        check(" 8 second" in delays[3][2], "the announced delay doubles: 1, 2, 4, 8 seconds")
        s.send_line(GOOD_PW)
        s.expect("Authenticated.", 60)
        check(True, "the correct password still works after 4 failures: the delay is temporary, not a lock-out")
        s.expect(PROMPT)
        end(s)
        info("the delay is per process (restarting sfm starts again at 1 s), but every guess still costs "
             "one Argon2id computation; the delay is capped at 30 s")
    brute_force()

    @scenario("Failed attempts must be written to the log")
    def logged():
        events = [json.loads(l) for l in open(box.log) if l.strip()]
        fails = [e for e in events if e["event"] == "login" and e["outcome"] == "failure"]
        check(len(fails) >= 10, f"every failed login is logged ({len(fails)} failures recorded)")
    logged()


# ======================================================================
#  3. COMMANDS
# ======================================================================
def test_commands(exe):
    R.section("3. COMMANDS: encrypt, decrypt, secure_delete, exit")
    box = Box(exe, "commands")
    s = register(box)
    scanner = memory_scanner_works(s)
    if not scanner:
        skip("RAM checks: the memory scanner could not find a known string in the process")

    marker, content = make_content("BIG")
    big = box.write(box.work, "big_file.txt", content)
    vault_big = f"{box.vault}/big_file.txt.sfm"

    # ------------------------------------------------------------ ENCRYPT
    @scenario("ENCRYPT: file is encrypted and placed inside the vault; the source is wiped")
    def encrypt_basic():
        twin = os.path.join(box.root, "twin_of_big_file")
        os.link(big, twin)                                  # second name for the same disk blocks
        out = s.run(f"encrypt {q(big)}")
        check("Encrypted:" in out and os.path.isfile(vault_big), "encrypted file 'big_file.txt.sfm' is in the vault", out)
        blob = open(vault_big, "rb").read()
        check(blob[:4] == b"SFM1" and marker not in blob, "it is real ciphertext (SFM1 header, plaintext not visible)")
        check(mode(vault_big) == 0o600, "vault file is private (0600)")
        check(not os.path.exists(big), "the source file no longer exists")
        data = open(twin, "rb").read()
        check(len(data) == len(content) and data.count(0) == len(data),
              "DISK: the old blocks of the source were overwritten with zeros (read through a hard link)")
        check(files_containing(box.root, marker) == [], "DISK: the plaintext is nowhere in the test area")
        check(leftovers(box.work, box.vault) == [], "no temporary file is left behind")
        if scanner:
            check(s.scan_memory([marker])[marker] == 0, "RAM: the plaintext is not in the process memory after encrypting")
        os.unlink(twin)
    encrypt_basic()

    @scenario("ENCRYPT: paths must be absolute and are resolved")
    def encrypt_paths():
        out = s.run("encrypt relative.txt")
        check("absolute" in out, "a relative path is refused", out)
        out = s.run(f"encrypt {box.work}/../work/x")
        check("traversal" in out, "a path with '..' is refused", out)
        out = s.run(f"encrypt {q(box.work + '/')}")
        check("not a directory" in out or "must name a file" in out, "a directory is refused", out)
        real = os.path.join(box.root, "realdir")
        os.mkdir(real)
        link = os.path.join(box.root, "linkdir_XYZ")
        os.symlink(real, link)
        box.write(real, "via_link.txt", b"hello")
        out = s.run(f"encrypt {q(link + '/via_link.txt')}")
        check("Encrypted:" in out and f"'{real}/via_link.txt'" in out and "linkdir_XYZ" not in out,
              "a path through a symlinked folder is resolved to the real absolute path", out)
        check(not os.path.exists(f"{real}/via_link.txt") and os.path.isfile(f"{box.vault}/via_link.txt.sfm"),
              "the real file was encrypted and removed")
        s.run('secure_delete "via_link.txt.sfm"')
    encrypt_paths()

    @scenario("ENCRYPT: a symbolic link must be refused")
    def encrypt_symlink():
        target = box.write(box.work, "link_target.txt", b"do not touch")
        link = os.path.join(box.work, "a_link.txt")
        os.symlink(target, link)
        before = box.vault_files()
        out = s.run(f"encrypt {q(link)}")
        check("symlink" in out and os.path.islink(link), "encrypting a link is refused and the link is untouched", out)
        check(open(target, "rb").read() == b"do not touch" and box.vault_files() == before,
              "the file it points to is untouched and nothing entered the vault")
        os.unlink(link), os.unlink(target)
    encrypt_symlink()

    @scenario("ENCRYPT: paths and names that are too long must be refused")
    def encrypt_long():
        out = s.run("encrypt /" + "a" * 1100)
        check("Line too long" in out, "a command line over 1023 characters is refused", out)
        out = s.run("encrypt /" + "/".join(["d" * 100] * 5) + "/" + "f" * 300)
        check("encrypt:" in out and "Encrypted" not in out and not crashed(out),
              "a long path with a 300-character name is refused cleanly", out)
        name = "n" * 252                                   # 252 + ".sfm" exceeds the 255-byte file name limit
        p = box.write(box.work, name, b"x" * 100)
        out = s.run(f"encrypt {q(p)}")
        check("Encrypted" not in out and os.path.exists(p) and leftovers(box.work, box.vault) == [],
              "a name that cannot fit in the vault is refused; the source is kept, no temporary file left", out)
        os.unlink(p)
        p = box.write(box.work, "m" * 200, b"y")
        out = s.run(f"encrypt {q(p)}")
        check("Encrypted:" in out, "a long but valid name (200 characters) still works", out)
        s.run(f'secure_delete "{"m" * 200}.sfm"')
        info("validate.c also rejects paths of 4096+ bytes, but the shell line limit (1023) is hit first")
    encrypt_long()

    @scenario("ENCRYPT: files that belong to another user must be refused")
    def encrypt_foreign():
        before = open("/etc/passwd", "rb").read()
        out = s.run("encrypt /etc/passwd")
        check("another user" in out, "/etc/passwd (owned by root) is refused", out)
        check(open("/etc/passwd", "rb").read() == before and "passwd.sfm" not in box.vault_files(),
              "the file is unchanged and nothing entered the vault")
    encrypt_foreign()

    @scenario("ENCRYPT: a file whose name already exists in the vault must be refused")
    def encrypt_collision():
        other_dir = os.path.join(box.root, "other")
        os.mkdir(other_dir)
        dup = box.write(other_dir, "big_file.txt", b"a DIFFERENT file with the same name")
        before = open(vault_big, "rb").read()
        out = s.run(f"encrypt {q(dup)}")
        check("already exists" in out, "big_file.txt is refused: big_file.txt.sfm is already in the vault", out)
        check(open(dup, "rb").read() == b"a DIFFERENT file with the same name", "the new source file is kept")
        check(open(vault_big, "rb").read() == before, "the existing vault file was not overwritten")
        check(leftovers(other_dir, box.vault) == [], "no temporary file is left behind")
    encrypt_collision()

    # ------------------------------------------------------------ DECRYPT
    @scenario("DECRYPT: the file is placed in the destination and the encrypted copy stays")
    def decrypt_basic():
        before = open(vault_big, "rb").read()
        out = s.run(f"decrypt big_file.txt.sfm {q(box.dest)}")
        out_file = f"{box.dest}/big_file.txt"
        check("Decrypted:" in out and f"'{out_file}'" in out, "decrypt reports the absolute destination path", out)
        check(os.path.isfile(out_file) and open(out_file, "rb").read() == content,
              "the decrypted file is in the destination and identical to the original")
        check(mode(out_file) == 0o600, "the decrypted file is private (0600)")
        check(open(vault_big, "rb").read() == before, "the encrypted file is still in the vault, unchanged")
        check(leftovers(box.dest, box.vault) == [], "no temporary file is left behind")
        if scanner:
            check(s.scan_memory([marker])[marker] == 0, "RAM: the plaintext is not in the process memory after decrypting")
    decrypt_basic()

    @scenario("DECRYPT: the destination must be an absolute path and is resolved")
    def decrypt_paths():
        out = s.run("decrypt big_file.txt.sfm relative_dir")
        check("absolute" in out, "a relative destination is refused", out)
        out = s.run(f"decrypt big_file.txt.sfm {box.dest}/../dest")
        check("traversal" in out, "a destination with '..' is refused", out)
        out = s.run(f"decrypt big_file.txt.sfm {q(box.root + '/does_not_exist')}")
        check("not an existing directory" in out, "a missing destination is refused", out)
        out = s.run(f"decrypt big_file.txt.sfm {q(vault_big)}")
        check("not an existing directory" in out, "a file as destination is refused", out)
        real = os.path.join(box.root, "real_dest")
        os.mkdir(real)
        link = os.path.join(box.root, "dest_link_XYZ")
        os.symlink(real, link)
        out = s.run(f"decrypt big_file.txt.sfm {q(link)}")
        check("Decrypted:" in out and f"'{real}/big_file.txt'" in out and "dest_link_XYZ" not in out,
              "a symlinked destination is resolved to the real absolute path", out)
        check(os.path.isfile(f"{real}/big_file.txt"), "the file really is in the resolved folder")
        for bad in ("../x.sfm", "a/b.sfm", "/etc/passwd"):
            out = s.run(f"decrypt {q(bad)} {q(box.dest)}")
            check("must not contain '/'" in out, f"vault file name {bad!r} cannot escape the vault", out)
    decrypt_paths()

    @scenario("DECRYPT: paths that are too long must be refused")
    def decrypt_long():
        out = s.run("decrypt big_file.txt.sfm /" + "a" * 1100)
        check("Line too long" in out, "a command line over 1023 characters is refused", out)
        out = s.run("decrypt big_file.txt.sfm /" + "/".join(["d" * 100] * 5) + "/" + "f" * 300)
        check("not an existing directory" in out and not crashed(out), "a long destination path is refused cleanly", out)
        out = s.run("decrypt " + "z" * 300 + ".sfm " + q(box.dest))
        check("Decrypted" not in out and not crashed(out), "a 300-character vault file name is refused cleanly", out)
    decrypt_long()

    @scenario("DECRYPT: an existing file in the destination must not be overwritten")
    def decrypt_collision():
        victim_dir = os.path.join(box.root, "collision")
        os.mkdir(victim_dir)
        existing = box.write(victim_dir, "big_file.txt", b"I was here first")
        out = s.run(f"decrypt big_file.txt.sfm {q(victim_dir)}")
        check("already exists" in out, "decrypt refuses: big_file.txt already exists in the destination", out)
        check(open(existing, "rb").read() == b"I was here first" and leftovers(victim_dir) == [],
              "the existing file is unchanged and no temporary file is left")
    decrypt_collision()

    # ------------------------------------------------------------ SECURE DELETE
    @scenario("SECURE_DELETE: inside the vault")
    def delete_in_vault():
        m2, c2 = make_content("VAULTDEL")
        p = box.write(box.work, "to_delete.txt", c2)
        s.run(f"encrypt {q(p)}")
        vf = f"{box.vault}/to_delete.txt.sfm"
        twin = os.path.join(box.root, "twin_vault_file")
        os.link(vf, twin)
        out = s.run("secure_delete to_delete.txt.sfm")
        check("Deleted:" in out and not os.path.exists(vf), "a file is deleted from the vault by name", out)
        data = open(twin, "rb").read()
        check(len(data) > 0 and data.count(0) == len(data), "DISK: its blocks were overwritten with zeros")
        os.unlink(twin)
        check(files_containing(box.root, m2) == [], "DISK: no trace of the content anywhere")
        if scanner:
            check(s.scan_memory([m2])[m2] == 0, "RAM: no trace of the content in the process memory")
        # by absolute path too
        p = box.write(box.work, "to_delete2.txt", b"x" * 1000)
        s.run(f"encrypt {q(p)}")
        out = s.run(f"secure_delete {q(box.vault + '/to_delete2.txt.sfm')}")
        check("Deleted:" in out and "to_delete2.txt.sfm" not in box.vault_files(), "or by its absolute path", out)
    delete_in_vault()

    @scenario("SECURE_DELETE: outside the vault (the user's own files only)")
    def delete_outside():
        m3, c3 = make_content("OUTSIDE")
        p = box.write(box.work, "outside.txt", c3)
        twin = os.path.join(box.root, "twin_outside")
        os.link(p, twin)
        out = s.run(f"secure_delete {q(p)}")
        check("Deleted:" in out and not os.path.exists(p), "a file outside the vault is deleted", out)
        data = open(twin, "rb").read()
        check(len(data) == len(c3) and data.count(0) == len(data), "DISK: its blocks were overwritten with zeros")
        os.unlink(twin)
        check(files_containing(box.root, m3) == [], "DISK: no trace of the content anywhere")
        if scanner:
            check(s.scan_memory([m3])[m3] == 0, "RAM: no trace of the content in the process memory")
        before = open("/etc/passwd", "rb").read()
        out = s.run("secure_delete /etc/passwd")
        check(("another user" in out or "cannot open" in out) and os.path.exists("/etc/passwd")
              and open("/etc/passwd", "rb").read() == before,
              "a file of another user (/etc/passwd) is refused and unchanged", out)
        out = s.run("secure_delete relative/file.txt")
        check("absolute" in out, "a relative path is refused", out)
        out = s.run(f"secure_delete {box.work}/../work/x")
        check("traversal" in out, "a path with '..' is refused", out)
        out = s.run(f"secure_delete {q(box.work)}")
        check("Deleted" not in out and os.path.isdir(box.work), "a directory is refused", out)
        target = box.write(box.work, "sym_target.txt", b"keep me")
        os.symlink(target, f"{box.work}/sym_link.txt")
        out = s.run(f"secure_delete {q(box.work + '/sym_link.txt')}")
        check("Deleted" not in out and open(target, "rb").read() == b"keep me",
              "a symbolic link is refused and its target is untouched", out)
        out = s.run("secure_delete notes.txt")
        check("Deleted" not in out and "'.sfm'" in out, "a bare name that is not a vault file is refused", out)
    delete_outside()

    # ------------------------------------------------------------ EXIT
    @scenario("EXIT: graceful termination")
    def exit_graceful():
        check(s.core_limit() == ["0", "0"], "core dumps are disabled (no secrets in a crash dump)", s.core_limit())
        locked = s.proc_status("VmLck")
        if locked.split()[0] != "0":
            check(True, f"key memory is locked in RAM, never swapped (VmLck = {locked})")
        else:
            skip("VmLck is 0 kB: not reported by this build/kernel (sanitizer Debug builds, some sandboxes); run the Release build to confirm mlock")
        s.send_eof()                                       # Ctrl-D must not quit or crash
        s.expect("Use 'exit' to quit.")
        s.expect(PROMPT)
        check(s.alive(), "Ctrl-D at the prompt does not terminate or crash the program")
        os.kill(s.pid, signal.SIGINT)
        os.kill(s.pid, signal.SIGTSTP)
        time.sleep(0.3)
        check(s.alive() and not s.proc_status("State").startswith("T"),
              "Ctrl-C / Ctrl-Z are ignored (the process cannot be suspended with secrets in RAM)")
        out = s.run("list")
        check("big_file.txt.sfm" in out, "the program is still fully functional afterwards", out)
        s.send_line("exit")
        code = s.wait()
        check(code == 0 and not crashed(s.transcript), "'exit' ends with status 0 and no crash/sanitizer report", s.transcript[-300:])
        check(s.echo_enabled(), "the terminal is left in a normal state (echo on)")
        check(leftovers(box.work, box.vault, box.dest) == [], "no temporary file is left behind")
        info("RAM after exit: a terminated process's memory cannot be inspected; the wiping of the key and of "
             "the buffers is verified in-session (sections 3 and 4) and by the termination test below")
    exit_graceful()

    @scenario("EXIT: termination signal at a password prompt")
    def exit_sigterm():
        s2 = Sfm(box)
        s2.expect("Master password: ")
        check(not s2.echo_enabled(), "while the password is typed the terminal echo is off")
        s2.expected_signal = True
        os.kill(s2.pid, signal.SIGTERM)
        code = s2.wait()
        check(code == 128 + signal.SIGTERM, f"SIGTERM ends the program in a controlled way (status {code})")
        check(s2.echo_enabled(), "the handler restored the terminal echo before exiting")
    exit_sigterm()
    s.close()


# ======================================================================
#  4. BEHAVIOR
# ======================================================================
def test_behavior(exe):
    R.section("4. BEHAVIOR: passwords in RAM, the log, tampered files")

    # ---------------------------------------------------------------- RAM
    @scenario("Passwords must not stay in RAM after use")
    def ram():
        box = Box(exe, "ram")
        pw = "RamTest!Passw0rd-" + f"{random.SystemRandom().getrandbits(32):08x}"
        wrong = "WrongRam!Guess-" + f"{random.SystemRandom().getrandbits(32):08x}"
        s = Sfm(box)
        s.expect("Choose a master password: ")
        s.send_line(pw)
        s.expect("Confirm master password: ")
        s.send_line(pw)
        s.expect("Please log in to continue.", 60)
        s.expect("Master password: ")
        s.send_line(wrong)
        s.expect("Wrong password")
        s.expect("Master password: ", 20)
        s.send_line(pw)
        s.expect("Authenticated.", 60)
        s.expect(PROMPT)
        # Scan FIRST, before typing anything else: the next command would overwrite stdio's input buffer.
        try:
            hits = s.scan_memory([pw, wrong])
        except OSError as e:
            skip(f"cannot read the process memory ({e})")
            end(s)
            return
        if not memory_scanner_works(s):          # positive control, done after the first scan
            skip("the memory scanner could not find a known string in the process; the RAM result is not trustworthy")
            end(s)
            return
        check(hits[pw.encode()] == 0, "the master password is not in RAM right after setup and login",
              f"{hits[pw.encode()]} copies found")
        check(hits[wrong.encode()] == 0, "a wrong password guess is not in RAM either",
              f"{hits[wrong.encode()]} copies found")
        s.run("help")
        hits = s.scan_memory([pw])
        check(hits[pw.encode()] == 0, "still not in RAM after running commands", f"{hits[pw.encode()]} copies found")
        end(s)
        check(files_containing(box.root, pw.encode()) == [], "the password is not in any file on disk (config, vault, log)")
    ram()

    # ---------------------------------------------------------------- LOG
    @scenario("The log must not expose sensitive information")
    def log_content():
        box = Box(exe, "log")
        s = Sfm(box)
        s.expect("Choose a master password: ")
        s.send_line(GOOD_PW)
        s.expect("Confirm master password: ")
        s.send_line(GOOD_PW)
        s.expect("Please log in to continue.", 60)
        s.expect("Master password: ")
        s.send_line("LogWrong!Guess-12345")
        s.expect("Wrong password")
        s.expect("Master password: ", 20)
        s.send_line(GOOD_PW)
        s.expect("Authenticated.", 60)
        s.expect(PROMPT)
        marker, content = make_content("LOG")
        names = ["plain.txt", "semi;touch X.txt", "esc\x1b[31mred.txt", "dollar$(id).txt"]
        for n in names:
            p = box.write(box.work, n, content)
            s.run(f"encrypt {q(p)}")
            s.run(f'decrypt {q(n + ".sfm")} {q(box.dest)}')
            s.run(f'secure_delete {q(n + ".sfm")}')
        s.run("list")
        s.run("decrypt missing.sfm " + q(box.dest))
        end(s)
        text = open(box.log, "rb").read()
        secrets = {"master password": GOOD_PW, "wrong guess": "LogWrong!Guess-12345",
                   "file content": marker.decode(), "temp directory path": box.root}
        for label, secret in secrets.items():
            check(secret.encode() not in text, f"the log does not contain the {label}")
        lines = text.decode("utf-8", "replace").splitlines()
        records, bad = [], []
        for line in lines:
            try:
                records.append(json.loads(line))
            except ValueError:
                bad.append(line)
        check(not bad and len(records) > 20, f"all {len(lines)} lines are valid JSON records (one record per line)", bad[:2])
        fields = {"timestamp", "event", "user", "source", "outcome"}
        check(all(fields <= set(r) for r in records), "each record has timestamp, event, user, source and outcome")
        check(all(r["outcome"] in ("success", "failure") for r in records), "outcomes are only success or failure")
        check(all(r["user"].startswith("uid=") for r in records), "the user is identified by uid only")
        check(b"\x1b" not in text, "control characters from file names are neutralised (no log injection)")
        targets = {r["target"] for r in records if "target" in r}
        check(all("/" not in t for t in targets), "only base names are logged, never directories", sorted(targets)[:4])
        events = {(r["event"], r["outcome"]) for r in records}
        check({("login", "failure"), ("login", "success"), ("master_password_setup", "success"),
               ("file_encrypt", "success"), ("file_decrypt", "success"), ("file_delete", "success"),
               ("list_files", "success"), ("file_decrypt", "failure")} <= events,
              "all the key events are recorded (setup, login success/failure, encrypt, decrypt, delete, list)")
    log_content()

    # ---------------------------------------------------------------- TAMPERING
    R.sub("Tampering with the essential files and folders")
    box = Box(exe, "tamper")
    s = register(box)
    keep_content = b"content that must survive tampering " * 50
    keep = box.write(box.work, "keep.txt", keep_content)
    s.run(f"encrypt {q(keep)}")
    end(s)
    box.snapshot()
    vault_keep = f"{box.vault}/keep.txt.sfm"

    def start_expecting_failure(note):
        """Start sfm and see how it reacts; returns the finished session when it refuses to start."""
        t = Sfm(box)
        try:
            t.expect("Master password: ", 15)
            return t, True
        except FlowError:
            code = t.wait(20) if t.code is None else t.code
            return t, False

    def refuses_cleanly(label, expected_text=None):
        t, started = start_expecting_failure(label)
        if started:
            t.close()
            check(False, f"{label}: sfm should have refused to start", t.transcript)
            return
        ok = t.code != 0 and not crashed(t.transcript)
        if expected_text:
            ok = ok and expected_text.lower() in t.transcript.lower()
        check(ok, f"{label}: sfm refuses with a clear message, no crash", t.transcript.strip()[-200:])

    def still_works(label, expect_vault_file=True):
        t = login(box)
        out = t.run("list")
        check(True, f"{label}: sfm starts and the master password still works")
        if expect_vault_file is not None:
            check(("keep.txt.sfm" in out) == expect_vault_file,
                  f"  vault content as expected ({'file present' if expect_vault_file else 'file gone'})", out)
        end(t)
        return t

    @scenario("Folder and file deleted: sfm recreates what is missing")
    def deleted():
        box.restore()
        shutil.rmtree(f"{box.home}/.local/share/sfm")
        still_works("vault folder deleted", expect_vault_file=False)
        check(os.path.isdir(box.vault) and mode(box.vault) == 0o700, "  the vault folder was recreated (0700)")
        box.restore()
        os.unlink(box.log)
        still_works("log file deleted")
        check(os.path.isfile(box.log) and mode(box.log) == 0o600, "  the log file was recreated (0600)")
        box.restore()
        os.unlink(vault_keep)
        out = (t := login(box)).run("list")
        check("vault is empty" in out, "a vault file deleted by hand: the vault is simply empty", out)
        out = t.run(f"decrypt keep.txt.sfm {q(box.dest)}")
        check("not found" in out, "  and decrypting it reports 'file not found'", out)
        end(t)
    deleted()

    @scenario("Configuration deleted: no silent re-initialisation over an existing vault")
    def config_deleted():
        box.restore()
        os.unlink(box.config)
        before = open(vault_keep, "rb").read()
        t = Sfm(box)
        code = t.wait(30)
        check(code != 0 and "Refusing first-run setup" in t.transcript and "Choose a master password" not in t.transcript,
              "sfm refuses to set a new password while the vault holds encrypted files", t.transcript)
        check(open(vault_keep, "rb").read() == before, "the encrypted files are untouched")
        box.restore()
        shutil.rmtree(f"{box.home}/.local/share/sfm")
        os.unlink(box.config)
        t = register(box, "NewMaster1!pw")
        check(True, "with an empty/missing vault a new master password can be registered again")
        end(t)
    config_deleted()

    @scenario("Configuration modified: wrong data must never give access or crash the program")
    def config_modified():
        cfg_text = open(box.config).read()
        cfg = json.loads(cfg_text)

        def write_cfg(data):
            with open(box.config, "w") as f:
                f.write(data if isinstance(data, str) else json.dumps(data))
            os.chmod(box.config, 0o600)

        corrupt = {
            "garbage bytes": "\x00\xff\xfe not json at all",
            "empty file": "",
            "truncated JSON": cfg_text[: len(cfg_text) // 2],
            "wrong value types": json.dumps({k: 123 for k in cfg}),
            "oversized file (200 KB)": "x" * 200_000,
            "relative vault path": json.dumps({**cfg, "vault": "relative/vault"}),
            "vault path with '..'": json.dumps({**cfg, "vault": cfg["vault"] + "/../x"}),
            "'config' field pointing elsewhere": json.dumps({**cfg, "config": "/tmp/other.config"}),
        }
        for label, data in corrupt.items():
            box.restore()
            write_cfg(data)
            refuses_cleanly(f"configuration with {label}", "configuration")
            check(os.path.exists(vault_keep), "  the vault was not touched")

        box.restore()
        write_cfg({**cfg, "verifier": "A" * 43 + "="})
        t = Sfm(box)
        t.expect("Master password: ")
        t.send_line(GOOD_PW)
        t.expect("Wrong password", 40)
        t.expect("Master password: ", 20)
        t.send_eof()
        t.wait()
        check("Authenticated" not in t.transcript, "a modified verifier: even the right password no longer logs in")

        box.restore()
        other_salt = ("AAAA" if not cfg["salt"].startswith("AAAA") else "BBBB") + cfg["salt"][4:]
        write_cfg({**cfg, "salt": other_salt})
        t = Sfm(box)
        t.expect("Master password: ")
        t.send_line(GOOD_PW)
        t.expect("Wrong password", 40)
        t.expect("Master password: ", 20)
        t.send_eof()
        t.wait()
        check("Authenticated" not in t.transcript, "a modified salt: the right password no longer logs in")

        box.restore()
        write_cfg({**cfg, "salt": "!!not base64!!"})
        refuses_cleanly("a salt that is not valid Base64", "corrupt")
        box.restore()
        write_cfg({**cfg, "kdf": "md5"})
        refuses_cleanly("an unsupported kdf name", "corrupt")
        box.restore()
        write_cfg({**cfg, "salt": "", "verifier": ""})
        t = Sfm(box)
        code = t.wait(30)
        check(code != 0 and "Refusing first-run setup" in t.transcript,
              "credentials erased from the configuration: no new password is accepted over the existing vault", t.transcript)
    config_modified()

    @scenario("Permissions changed: sfm repairs them")
    def permissions():
        box.restore()
        os.chmod(box.config, 0o666)
        os.chmod(box.vault, 0o777)
        os.chmod(box.log, 0o666)
        os.chmod(os.path.dirname(box.config), 0o755)
        still_works("permissions opened to everybody")
        check(mode(box.config) == 0o600 and mode(box.vault) == 0o700 and mode(box.log) == 0o600
              and mode(os.path.dirname(box.config)) == 0o700,
              "  config 0600, vault 0700, log 0600, config folder 0700 again")
        box.restore()
        os.chmod(box.log, 0o000)
        t, started = start_expecting_failure("log 000")
        if started:
            end_ok = True
            t.close()
        info(f"log file with mode 000: sfm {'starts' if started else 'refuses to start with: ' + t.transcript.strip()[-120:]}")
        check(not crashed(t.transcript), "  and does not crash")
        os.chmod(box.log, 0o600)
    permissions()

    @scenario("Files replaced by links or other types: sfm refuses and follows nothing")
    def replaced():
        victim = box.write(box.root, "victim.txt", b"VICTIM-ORIGINAL")
        victim_dir = os.path.join(box.root, "victim_dir")
        os.mkdir(victim_dir)

        def replace(path, how):
            if os.path.islink(path) or os.path.isfile(path):
                os.unlink(path)
            else:
                shutil.rmtree(path)
            if how == "symlink to a file":
                os.symlink(victim, path)
            elif how == "symlink to a folder":
                os.symlink(victim_dir, path)
            elif how == "folder":
                os.mkdir(path)
            elif how == "regular file":
                open(path, "w").write("x")

        for label, path, how in [
            ("log replaced by a symlink", box.log, "symlink to a file"),
            ("log replaced by a folder", box.log, "folder"),
            ("configuration replaced by a symlink", box.config, "symlink to a file"),
            ("configuration replaced by a folder", box.config, "folder"),
            ("vault replaced by a symlink", box.vault, "symlink to a folder"),
            ("vault replaced by a regular file", box.vault, "regular file"),
            ("config folder replaced by a symlink", os.path.dirname(box.config), "symlink to a folder"),
        ]:
            box.restore()
            replace(path, how)
            refuses_cleanly(label, "symlinks are refused" if "symlink" in how else None)
            check(open(victim, "rb").read() == b"VICTIM-ORIGINAL" and os.listdir(victim_dir) == [],
                  "  nothing was written through the link")
    replaced()

    @scenario("Vault files modified: decryption fails cleanly and sfm keeps working")
    def vault_tampered():
        original = open(f"{box.vault}/keep.txt.sfm", "rb").read() if os.path.exists(vault_keep) else None
        box.restore()
        original = open(vault_keep, "rb").read()
        flipped = bytearray(original)
        flipped[-1] ^= 1
        header_flip = bytearray(original)
        header_flip[40] ^= 1
        cases = {
            "one byte changed at the end": bytes(flipped),
            "one byte changed in the key header": bytes(header_flip),
            "truncated": original[: len(original) // 2],
            "data appended": original + b"extra",
            "replaced by random bytes": os.urandom(500),
            "emptied": b"",
        }
        t = login(box)
        for label, data in cases.items():
            with open(vault_keep, "wb") as f:
                f.write(data)
            out = t.run(f"decrypt keep.txt.sfm {q(box.dest)}")
            check("Decrypted" not in out and not os.path.exists(f"{box.dest}/keep.txt") and not crashed(out)
                  and ("modified" in out or "not a valid" in out),
                  f"vault file {label}: refused with a generic message, no output file", out)
        check(leftovers(box.dest, box.vault) == [], "no temporary file is left behind")
        os.unlink(vault_keep)
        p = box.write(box.work, "after.txt", b"still working")
        out = t.run(f"encrypt {q(p)}")
        check("Encrypted:" in out, "sfm still works normally after the tampered files", out)
        end(t)
    vault_tampered()

    @scenario("Log file modified: sfm keeps working and only appends")
    def log_tampered():
        box.restore()
        garbage = os.urandom(50_000)
        with open(box.log, "wb") as f:
            f.write(garbage)
        t = login(box)
        t.run("list")
        end(t)
        data = open(box.log, "rb").read()
        check(data.startswith(garbage) and len(data) > len(garbage),
              "a log filled with garbage does not stop sfm; new records are appended after it")
    log_tampered()

    # ---------------------------------------------------------------- crash check
    R.sub("Whole run")
    bad = [s for s in SESSIONS if crashed(s.transcript) or (s.code is not None and s.code >= 128 and not s.expected_signal
                                                           and s.code not in (128 + signal.SIGTERM,))]
    check(not bad, "no sfm process crashed or produced a sanitizer/runtime error report during the whole run",
          [s.transcript[-200:] for s in bad[:2]])


# ======================================================================
def main():
    global KEEP
    ap = argparse.ArgumentParser(description="End-to-end test of sfm")
    ap.add_argument("exe", help="path of the sfm executable")
    ap.add_argument("--only", default="init,access,commands,behavior", help="comma-separated sections to run")
    ap.add_argument("--keep", action="store_true", help="keep the temporary folders (for debugging)")
    args = ap.parse_args()
    KEEP = args.keep

    exe = os.path.realpath(args.exe)
    if os.geteuid() == 0:
        print("SKIP: sfm refuses to run as root; run this test as a normal user")
        return 77
    if not os.access(exe, os.X_OK):
        print(f"error: {exe} is not an executable (build it first)")
        return 2

    sections = {"init": test_initialization, "access": test_access,
                "commands": test_commands, "behavior": test_behavior}
    started = time.monotonic()
    for name in args.only.split(","):
        sections[name.strip()](exe)

    print(f"\n{'=' * 72}")
    print(f"RESULT: {R.passed} passed, {R.failed} failed, {R.skipped} skipped "
          f"({time.monotonic() - started:.0f} s)")
    for f in R.failures:
        print(f"  FAILED: {f}")
    return 0 if R.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
