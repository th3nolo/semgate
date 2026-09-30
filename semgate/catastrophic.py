"""Catastrophic deletes and permission changes: a hard deny in every spelling.

The owner's rule: a command that destroys the whole system or the user's
home folder, and cannot be undone, is never approvable. A tired person can
say yes to an ask. So these commands are a hard deny (rules.check_hard_deny),
not a human gate. No approval, chat yes, `semgate feedback allow` or trust
entry opens a hard deny.

The regexes in rules.HARD_DENY_PATTERNS see `rm -rf /`, `rm -rf /*` and
`rm -rf ~` only when r comes before f in one flag group and `/` ends the
line. `rm -rf / --no-preserve-root`, `rm -fr /` and `rm -r -f /` were only a
human gate (destructive_irreversible), which a person can approve. This
module parses the command instead, the same way adminguard.py does:

- every simple command of the command and of the code it runs
  (shellparse.extract_scripts: bash -c, sh -c, eval, python -c with
  os.system, $(...), backticks, heredocs fed to a shell, find -exec, ssh,
  docker exec), plus `su -c`, `env -S` and a program word with spaces
  (`watch 'rm -rf /'`);
- wrappers skipped: env X=1, sudo [-u x], doas, nice, ionice, timeout,
  stdbuf, time, nohup, command, exec, xargs, busybox, and the shell words
  if, then, do, !, {, (;
- the program read by its base name through quotes, escapes and paths
  (\\rm, 'rm', /bin/rm, /usr/bin/rm, C:\\...\\rm.exe).

A simple command is a hard deny when it is:
1. rm with --no-preserve-root anywhere;
2. rm with a recursive flag (-r, -R, -rf, -fr, -Rf, -rfv, -r -f,
   --recursive) and a catastrophic target. Option parsing stops at `--`.
   Options after a target count, as in GNU rm (`rm / -rf`);
3. find with a catastrophic start folder and -delete, or with -exec,
   -execdir, -ok or -okdir that runs rm, unlink, shred, chmod, chown or chgrp.
   One exception: when the start folder is one user's home folder and find
   picks files by name or path (-name .DS_Store, not negated, not a
   match-all, no -o), the delete is targeted and the human gate asks;
4. chmod, chown or chgrp with -R or --recursive and a catastrophic target
   other than one user's home folder (`sudo chown -R $USER ~` repairs
   ownership; the human gate asks).

Catastrophic targets. Quotes are removed, repeated slashes are collapsed,
`.` and `..` are resolved. A trailing `/`, `/*`, `/.*` or `/.` counts as the
folder itself. Brace lists (`/{usr,etc}`) are expanded, and a glob at the top
level (`/us*`) is matched against the list.
- `/`;
- the home folder: ~, $HOME, ${HOME}, ~user, and $USERPROFILE,
  ${USERPROFILE}, $env:USERPROFILE, $env:HOME, %USERPROFILE%;
- the top-level system folders in TOP_LEVEL (Linux, macOS, /mnt, /media);
- one user's home folder: /home/<name>, /Users/<name>;
- /private/etc and /private/var (macOS);
- a Windows drive in its forms C:, C:\\, C:/, /c, /cygdrive/c, /mnt/c, and
  its folders Windows, Users, Program Files, Program Files (x86),
  ProgramData and Users/<name>.
A deeper path is not in the set: /home/me/project/build, /tmp/x, /var/tmp/x,
/usr/local/lib/node_modules/foo, ~/project/build.

A `cd` or `pushd` earlier in the same text sets the folder a relative target
is read against: `cd / && rm -rf *` is `rm -rf /*`.

Text that only mentions a command is not a hit: `echo "rm -rf /"`,
`grep -rn "rm -rf /" docs` and `git commit -m "rm -rf /"` have echo, grep
and git as their program.

Also seen now (added after 0.4.2):
- a variable program with a literal catastrophic target (`$R -rf /`,
  `${RM} -rf /`); the target still must be literal;
- a listing piped to a recursive delete (`find / | xargs rm -rf`,
  `find / -print0 | xargs -0 rm -rf`, from / or a system or home folder), with
  the same home-folder narrowing exception as find -delete;
- a recursive delete through a library call, in inline code or a script file
  (`shutil.rmtree("/")`, `os.removedirs("/")`, `subprocess.run(["rm","-rf","/"])`,
  Node `fs.rmSync("/", {recursive:true})`, Ruby `FileUtils.rm_rf("/")`), with the
  target given as "/", "~", `Path.home()`, `os.path.expanduser("~")` or
  `process.env.HOME`;
- ANSI-C escapes in the program word (`$'\\x72m' -rf /`);
- PowerShell `Remove-Item -Recurse` of / or the home folder;
- `rm -rf *` when the folder the command runs in (cwd) is / or the home folder.

Still only a human gate (ask): the target itself in a variable (`rm -rf "$DIR/"`,
`rm -rf "$DIR"/*`) - a legitimate build script writes this with $DIR set, so a
hard deny would block real work; the ask still catches the empty-variable wipe.
"""
from __future__ import annotations

import fnmatch
import re
from typing import List, Optional, Sequence, Tuple

from . import shellparse

MAX_DEPTH = 3
# Brace expansion limits, so a crafted word cannot make the check slow.
MAX_EXPANSIONS = 128
MAX_BRACE_WORD = 256
MAX_BRACE_PAIRS = 16
MAX_NAME = 255                                         # a longer path part is not a file name

TOP_LEVEL = frozenset({
    # Linux
    "bin", "boot", "dev", "etc", "home", "lib", "lib32", "lib64", "libx32", "opt", "proc", "root", "run", "sbin",
    "srv", "sys", "usr", "var",
    # mounted drives: WSL mounts the Windows drives under /mnt
    "mnt", "media",
    # macOS
    "applications", "library", "system", "users", "volumes", "private",
})
# /home/<name> and /Users/<name>: one user's home folder.
USER_PARENTS = frozenset({"home", "users"})
# macOS: /etc and /var are links to these.
PRIVATE_SYSTEM = frozenset({"etc", "var"})
# Folders at the root of a Windows drive.
WINDOWS_TOP = frozenset({"windows", "users", "program files", "program files (x86)", "programdata"})
# The home folder stands at /home/~ while a path is resolved: ~/.. is /home,
# ~/../.. is /, and /home/~ itself is a user's home folder.
HOME = "/home/~"
HOME_WORDS = ("${home}", "$home", "${userprofile}", "$userprofile", "$env:userprofile", "$env:home", "%userprofile%",
              "~")

DELETE_PROGRAMS = frozenset({"rm", "unlink", "shred"})
PERM_PROGRAMS = frozenset({"chmod", "chown", "chgrp"})
CD_PROGRAMS = frozenset({"cd", "pushd", "chdir", "set-location", "sl"})
SHELLS = frozenset(shellparse.SHELLS)
_CHECKED = DELETE_PROGRAMS | PERM_PROGRAMS | CD_PROGRAMS | SHELLS | {"find", "popd"}
_LETTERS = "abcdefghijklmnopqrstuvwxyz"

# Shell words in front of a command: `if rm ...`, `then rm ...`, `do rm ...`.
_KEYWORDS = frozenset({"if", "then", "else", "elif", "do", "while", "until", "coproc"})
# Programs that run the program named after their own options.
_WRAPPERS = frozenset(shellparse.WRAPPERS) | {"busybox"}
# Options of each wrapper that take the next word as their value.
_VALUE_OPTS = {
    "sudo": {"-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-U", "-T", "--user", "--group", "--host", "--prompt",
             "--close-from", "--chdir", "--role", "--type", "--other-user", "--command-timeout"},
    "doas": {"-u", "-C"},
    "env": {"-u", "-C", "-S", "--unset", "--chdir", "--split-string"},
    "nice": {"-n", "--adjustment"},
    "ionice": {"-c", "-n", "-p", "-P", "-u", "--class", "--classdata", "--pid", "--pgid", "--uid"},
    "timeout": {"-s", "-k", "--signal", "--kill-after"},
    "stdbuf": {"-i", "-o", "-e", "--input", "--output", "--error"},
    "time": {"-f", "-o", "--format", "--output"},
    "xargs": {"-a", "-d", "-E", "-I", "-L", "-n", "-P", "-s", "--arg-file", "--delimiter", "--max-lines",
              "--max-args", "--max-procs", "--max-chars", "--process-slot-var"},
    "watch": {"-n", "--interval"},
    "strace": {"-o", "-e", "-p", "-s", "-u", "-a", "-b", "-E", "-I", "-O", "-P", "-S", "-U", "-X"},
    "exec": {"-a"},
}
_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_NUMBER = re.compile(r"^\d+(?:\.\d+)?[smhd]?$")
_GLOB = re.compile(r"[*?\[]")
_MATCH_ALL = re.compile(r"^[.*?]*\*[.*?]*$")          # *, .*, *.*, .??*, **
_DROPPED = re.compile(r"[\^`]")                       # cmd and PowerShell escape characters
_MENTION = ("rm", "find", "chmod", "chown", "chgrp", "unlink", "shred")


# ---------------------------------------------------------------- words


def _strip_open(word: str) -> str:
    """A word that starts a subshell or group: `(rm`, `{`, `!`."""
    return word.lstrip("({!")


def _base(word: str) -> str:
    base = _DROPPED.sub("", word).replace("\\", "/").rsplit("/", 1)[-1].lower()
    return base[:-4] if base.endswith(".exe") else base


_ANSI_C_RE = re.compile(r"\\(x[0-9A-Fa-f]{1,2}|u[0-9A-Fa-f]{1,4}|U[0-9A-Fa-f]{1,8}|[0-7]{1,3}|.)")
_ANSI_C_SIMPLE = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b",
                  "f": "\f", "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?"}


def _ansi_c_decode(s: str) -> str:
    r"""The value of a bash $'...' word: \x72 -> r, \162 -> r, r -> r,
    \n \t \\ ... A crafted spelling like $'\x72m' -rf / is then read as rm."""
    def sub(m: "re.Match") -> str:
        g = m.group(1)
        try:
            if g[0] in "xuU":
                return chr(int(g[1:], 16))
            if g[0] in "01234567":
                return chr(int(g, 8) & 0xFF)
        except (ValueError, OverflowError):
            return g
        return _ANSI_C_SIMPLE.get(g, g)
    return _ANSI_C_RE.sub(sub, s)


def _unquote(raw: str) -> str:
    """A word as written, without its outer quotes ($'...' too). A $'...' word
    has its ANSI-C escapes decoded, the way bash reads it. A Windows path keeps
    its backslashes: cmd and PowerShell do not treat them as escapes."""
    ansi = len(raw) > 2 and raw[0] == "$" and raw[1] == "'"
    if len(raw) > 2 and raw[0] == "$" and raw[1] in "'\"":
        raw = raw[1:]
    if len(raw) > 1 and raw[0] == raw[-1] and raw[0] in "\"'":
        inner = raw[1:-1]
        return _ansi_c_decode(inner) if ansi else inner
    return raw


def _readings(simple: "shellparse.Simple") -> List[List[str]]:
    """Two readings of one simple command's words, redirects removed: the
    shell's values (quotes and escapes resolved) and the words as written
    without outer quotes."""
    words, skip = [], False
    for t in simple.tokens:
        if skip:
            skip = False
            continue
        if t.redirect:
            if not re.search(r"&\d$", t.raw) and not t.raw.startswith("<<"):
                skip = True                            # the redirect's target
            continue
        words.append(t)
    return [[t.value for t in words], [_unquote(t.raw) for t in words]]


def _program_argv(words: Sequence[str]) -> Tuple[List[str], List[str]]:
    """(the words from the real program on, code texts a wrapper runs).
    Skips shell words, variable assignments and wrappers with their
    options. `env -S '<cmd>'` and `su -c '<cmd>'` give their command as a
    code text; a program word with spaces (`watch 'rm -rf /'`) gives the
    rest of the words as one."""
    extra: List[str] = []
    i = 0
    while i < len(words):
        word = _strip_open(words[i])
        base = _base(word)
        if not word or base in _KEYWORDS or _ASSIGN.match(word):
            i += 1
            continue
        if base in ("su", "runuser"):
            for n, opt in enumerate(words[i + 1:], start=i + 1):
                if opt in ("-c", "--command") and n + 1 < len(words):
                    extra.append(words[n + 1])
                elif opt.startswith("--command="):
                    extra.append(opt.split("=", 1)[1])
                elif opt.startswith("-c") and len(opt) > 2 and not opt.startswith("--"):
                    extra.append(opt[2:])
            return [], extra
        if base in _WRAPPERS:
            opts = _VALUE_OPTS.get(base, set())
            i += 1
            while i < len(words) and base != "busybox":
                opt = words[i]
                if opt == "--":
                    i += 1
                    break
                if opt.startswith("-") and len(opt) > 1:
                    if base == "env":
                        if opt in ("-S", "--split-string") and i + 1 < len(words):
                            extra.append(words[i + 1])
                        elif opt.startswith("--split-string="):
                            extra.append(opt.split("=", 1)[1])
                        elif opt.startswith("-S") and len(opt) > 2:
                            extra.append(opt[2:])
                    i += 2 if opt in opts else 1
                    continue
                if _NUMBER.match(opt) or _ASSIGN.match(opt):
                    i += 1
                    continue
                break
            continue
        break
    if i >= len(words):
        return [], extra
    program = _strip_open(words[i])
    if re.search(r"\s", program.strip()) and _base(program) not in _CHECKED:
        # `watch 'rm -rf /'`: the program word is a command line. A path
        # with spaces to a known program ("C:\Program Files\...\rm.exe")
        # stays the program.
        extra.append(" ".join([program] + list(words[i + 1:])))
        return [], extra
    return [program] + list(words[i + 1:]), extra


# ---------------------------------------------------------------- targets


def _brace_span(word: str) -> Optional[Tuple[int, int, List[str]]]:
    """The first brace list `{a,b}` or sequence `{a..e}` in the word: (start,
    end, alternatives). `${...}` is a variable, not a list. One pass finds
    the pairs; at most MAX_BRACE_PAIRS pairs are looked at."""
    stack: List[int] = []
    pairs: List[Tuple[int, int]] = []
    for j, c in enumerate(word):
        if c == "{":
            stack.append(j)
        elif c == "}" and stack:
            pairs.append((stack.pop(), j))
    for i, j in sorted(pairs)[:MAX_BRACE_PAIRS]:
        if i > 0 and word[i - 1] == "$":
            continue
        parts, depth, last = [], 0, i + 1
        for k in range(i + 1, j):
            c = word[k]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            elif c == "," and depth == 0:
                parts.append(word[last:k])
                last = k + 1
        if parts:
            return i, j, parts + [word[last:j]]
        seq = re.fullmatch(r"([A-Za-z0-9])\.\.([A-Za-z0-9])", word[i + 1:j])
        if seq:
            a, b = ord(seq.group(1)), ord(seq.group(2))
            step = 1 if b >= a else -1
            return i, j, [chr(c) for c in range(a, b + step, step)]
    return None


def _expand_braces(word: str) -> List[str]:
    """The words a brace list expands to (`/{usr,etc}` -> /usr, /etc). A word
    longer than MAX_BRACE_WORD is not expanded; its pieces between braces
    and commas are checked as well (`{/aaa...,/}` still gives `/`)."""
    if "{" not in word or "}" not in word:
        return [word]
    if len(word) > MAX_BRACE_WORD:
        return [word] + [p for p in re.split(r"[{},]", word) if p]
    out: List[str] = []
    todo = [word]
    while todo:
        w = todo.pop()
        span = _brace_span(w) if len(out) + len(todo) < MAX_EXPANSIONS else None
        if span is None:
            out.append(w)
            continue
        a, b, alts = span
        todo.extend(w[:a] + alt + w[b + 1:] for alt in alts)
    return out


def _resolve(word: str, cwd: Optional[str]) -> Optional[str]:
    """The absolute path a target word names, with the home folder at HOME
    and a Windows drive at /mnt/<letter>. None when it depends on a folder
    that is not known (a relative path with no known cwd, ~-)."""
    w = word.strip().replace("\\", "/")
    if not w:
        return None
    low = w.lower()
    if low == "~+" or low.startswith("~+/"):
        if cwd is None:
            return None
        w = cwd + w[2:]
    elif low == "~-" or low.startswith("~-/"):
        return None
    else:
        home = next((h for h in HOME_WORDS if low == h or low.startswith(h + "/")), None)
        if home is not None:
            w = HOME + w[len(home):]
        else:
            user = re.match(r"^~([A-Za-z0-9._][A-Za-z0-9._-]*)(/.*)?$", w)
            if user:
                w = "/home/" + user.group(1) + (user.group(2) or "")
    drive = (re.match(r"^([A-Za-z]):(/.*)?$", w) or re.match(r"^/cygdrive/([A-Za-z])(/.*)?$", w, re.IGNORECASE)
             or re.match(r"^/([A-Za-z])(/.*)?$", w))
    if drive:
        w = "/mnt/" + drive.group(1).lower() + (drive.group(2) or "")
    if not w.startswith("/"):
        if cwd is None:
            return None
        # The cwd may be a Windows drive path (C:\Users\<name>, C:/Users/<name>):
        # resolve it the same way, so `rm -rf *` run from the home folder is
        # seen. A bare `/c/...` cwd is left as written: `/p` (a project root)
        # is a directory, not the C: drive, and a false hard deny is worse.
        base = _resolve(cwd, None) if (re.match(r"^[A-Za-z]:", cwd) or "\\" in cwd) else cwd
        w = (base or cwd) + "/" + w
    parts: List[str] = []
    for comp in w.split("/"):
        if comp in ("", "."):
            continue
        if comp == "..":
            if parts:
                parts.pop()
            continue
        parts.append(comp)
    return "/" + "/".join(parts)


def _matches(comp: str, names) -> bool:
    """The path part is one of the names, or a glob that matches one."""
    c = comp.lower()
    if len(c) > MAX_NAME:
        return False
    if _GLOB.search(c):
        return any(fnmatch.fnmatchcase(n, c) for n in names)
    return c in names


def _is_letter(comp: str) -> bool:
    """A drive letter, or a glob that matches one (`/?` is /c, /d ... in Git Bash)."""
    if len(comp) == 1 and comp.isalpha():
        return True
    return len(comp) <= MAX_NAME and bool(_GLOB.search(comp)) and any(
        fnmatch.fnmatchcase(ch, comp.lower()) for ch in _LETTERS)


def _catastrophic_parts(parts: List[str]) -> bool:
    if not parts:
        return True                                    # /
    last = parts[-1]
    if _MATCH_ALL.match(last):
        return _catastrophic_parts(parts[:-1])         # X/* is X
    n = len(parts)
    first = parts[0].lower()
    if n == 1:
        return _matches(last, TOP_LEVEL) or (bool(_GLOB.search(last)) and _is_letter(last))
    if first == "mnt" and _is_letter(parts[1]):       # a Windows drive
        if n == 2:
            return True
        if n == 3:
            return _matches(parts[2], WINDOWS_TOP)
        return n == 4 and parts[2].lower() == "users"
    if n == 2 and first in USER_PARENTS:
        return True                                    # one user's home folder
    return n == 2 and first == "private" and _matches(parts[1], PRIVATE_SYSTEM)


def _trim(word: str) -> str:
    """`(rm -rf /)`, `{ rm -rf /;}`: the lexer keeps an unbalanced closing
    parenthesis or brace on the last word."""
    while word[-1:] in (")", "}") and word.count(word[-1]) > word.count("(" if word[-1] == ")" else "{"):
        word = word[:-1]
    return word


def _user_home(parts: List[str]) -> bool:
    """One user's home folder (or its `/*`): /home/<name>, /Users/<name>, ~,
    or C:/Users/<name>. Not /home itself: that is every user's home."""
    while parts and _MATCH_ALL.match(parts[-1]):
        parts = parts[:-1]
    low = [p.lower() for p in parts]
    if len(low) == 2 and low[0] in USER_PARENTS:
        return True
    return len(low) == 4 and low[0] == "mnt" and _is_letter(parts[1]) and low[2] == "users"


def is_catastrophic(word: str, cwd: Optional[str] = None, home_ok: bool = False) -> bool:
    """True when the target word (or any word its braces expand to) is in
    the catastrophic set (module doc). With home_ok, one user's home folder
    does not count (see _perm_hit and _find_hit)."""
    if not isinstance(word, str) or not word:
        return False
    for w in _expand_braces(_trim(word)):
        path = _resolve(w, cwd)
        if path is None:
            continue
        parts = [p for p in path.split("/") if p]
        if _catastrophic_parts(parts) and not (home_ok and _user_home(parts)):
            return True
    return False


# ---------------------------------------------------------------- programs


def _rm_hit(args: Sequence[str], cwd: Optional[str]) -> str:
    recursive, no_preserve, done = False, False, False
    targets: List[str] = []
    for a in args:
        if a == "--no-preserve-root":
            no_preserve = True
        if not done and a == "--":
            done = True
            continue
        if not done and a.startswith("--") and len(a) > 2:
            # GNU rm takes any unique prefix of a long option: --rec, --no-pres
            name = a[2:].split("=", 1)[0].lower()
            if name and "recursive".startswith(name):
                recursive = True
            if name and "no-preserve-root".startswith(name):
                no_preserve = True
            continue
        if not done and a.startswith("-") and len(a) > 1:
            if "r" in a.lower():
                recursive = True
            continue
        targets.append(a)
    target = next((t for t in targets if is_catastrophic(t, cwd)), None) if recursive else None
    if target is not None:
        return f"recursive rm of {_trim(target)}" + (" with --no-preserve-root" if no_preserve else "")
    if no_preserve:
        return "rm --no-preserve-root"
    return ""


def _programs_of(words: Sequence[str], depth: int) -> List[str]:
    """Base names of the programs a word list runs: its program, and for a
    shell with -c, the programs of that code."""
    argv, extra = _program_argv(words)
    names = [_base(argv[0])] if argv else []
    codes = list(extra)
    if argv and names[0] in SHELLS:
        for n, a in enumerate(argv[1:], start=1):
            if a == "-c" and n + 1 < len(argv):
                codes.append(argv[n + 1])
                break
    if depth < MAX_DEPTH:
        for code in codes:
            try:
                simples = shellparse.split_commands(code)
            except Exception:
                continue
            for simple in simples:
                names += _programs_of(_readings(simple)[0], depth + 1)
    return names


# find tests that pick files by name or path.
_FIND_NAME_TESTS = frozenset({"-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename",
                              "-regex", "-iregex", "-lname", "-ilname"})
_MATCH_ALL_REGEX = frozenset({".*", ".+", "^.*$", "^.*", ".*$", ".*.*"})


def _find_narrowed(expr: Sequence[str]) -> bool:
    """find deletes only files that match a name or path pattern: at least one
    such test, not negated, whose pattern is not a match-all, and no -o in the
    expression (an either/or can widen the match again)."""
    if any(e in ("-o", "-or", ",") for e in expr):
        return False
    for k in range(len(expr) - 1):
        test, pattern = expr[k], expr[k + 1]
        if test not in _FIND_NAME_TESTS:
            continue
        if k and expr[k - 1] in ("!", "\\!", "-not"):
            continue
        if test in ("-regex", "-iregex"):
            if pattern.strip() in _MATCH_ALL_REGEX:
                continue
        elif _MATCH_ALL.match(pattern) or not pattern or re.fullmatch(r"[*/?.]*", pattern):
            continue
        return True
    return False


def _find_hit(args: Sequence[str], cwd: Optional[str], depth: int) -> str:
    i, starts = 0, []
    while i < len(args):
        a = args[i]
        if a in ("-H", "-L", "-P", "-E", "-X", "-d", "-s", "-x") or (a.startswith("-O") and a[2:].isdigit()):
            i += 1
        elif a == "-D" and i + 1 < len(args):
            i += 2
        elif a == "-f" and i + 1 < len(args):
            starts.append(args[i + 1])
            i += 2
        else:
            break
    while i < len(args) and not (args[i].startswith("-") and len(args[i]) > 1) \
            and args[i] not in ("(", "!", ",", ")", "\\(", "\\!"):
        starts.append(args[i])
        i += 1
    expr = list(args[i:])
    starts = starts or ["."]
    what = "-delete" if "-delete" in expr else ""
    for k, e in enumerate(expr):
        if what:
            break
        if e in ("-exec", "-execdir", "-ok", "-okdir"):
            body = []
            for w in expr[k + 1:]:
                if w in (";", "\\;", "+"):
                    break
                body.append(w)
            names = _programs_of(body, depth)
            hit = next((p for p in names if p in DELETE_PROGRAMS or p in PERM_PROGRAMS), "")
            if hit:
                what = f"{e} {hit}"
    if not what:
        return ""
    # A delete by name or path in one user's home folder (find ~ -name .DS_Store
    # -delete) is a targeted cleanup: the human gate asks. From / or a system
    # folder it stays a hard deny whatever the filter.
    home_ok = _find_narrowed(expr)
    for s in starts:
        if is_catastrophic(s, cwd, home_ok=home_ok):
            return f"find {_trim(s)} {what}"
    return ""


def _perm_hit(program: str, args: Sequence[str], cwd: Optional[str]) -> str:
    recursive, done, reference = False, False, False
    targets: List[str] = []
    for a in args:
        if not done and a == "--":
            done = True
            continue
        if not done and a.startswith("--") and len(a) > 2:
            name = a[2:].split("=", 1)[0].lower()
            if len(name) >= 3 and "recursive".startswith(name):
                recursive = True
            if len(name) >= 3 and "reference".startswith(name):
                reference = True
            continue
        if not done and a.startswith("-") and len(a) > 1:
            if "R" in a:
                recursive = True
            continue
        targets.append(a)
    if program != "chmod" and not reference:
        # chown/chgrp: the first word is the owner or group (`root` is not /root).
        # chmod keeps its mode in the list: a mode (755, u+x) is never a target.
        targets = targets[1:]
    if recursive:
        # One user's home folder is left to the human gate: `sudo chown -R $USER ~`
        # repairs ownership. / and the system folders stay a hard deny.
        for t in targets:
            if is_catastrophic(t, cwd, home_ok=True):
                return f"recursive {program} of {_trim(t)}"
    return ""


def _cd_target(args: Sequence[str], cwd: Optional[str]) -> Optional[str]:
    k = 0
    while k < len(args) and args[k].startswith("-") and len(args[k]) > 1:
        if args[k] == "--":
            k += 1
            break
        if args[k].lower() in ("-path", "-literalpath") and k + 1 < len(args):
            k += 1
            break
        k += 1
    if k >= len(args):
        return HOME
    if args[k] == "-":
        return None
    return _resolve(args[k], cwd)


# ---------------------------------------------------------------- variable program

# A word that is only a variable reference: `$R`, `${RM}`. The program it names
# is not known, but `$R -rf /` still has a recursive flag and a literal
# catastrophic target, which no ordinary program takes.
_VAR_RE = re.compile(r"^\$\{[A-Za-z_][A-Za-z0-9_]*\}$|^\$[A-Za-z_][A-Za-z0-9_]*$")


def _is_var(word: str) -> bool:
    return bool(_VAR_RE.match(word.strip()))


# ---------------------------------------------------------------- PowerShell delete

# Remove-Item and its aliases. `Remove-Item -Recurse $HOME` and
# `Remove-Item -Recurse -Force -Path ~` wipe the home folder; the Unix rm rule
# and the Windows-drive regexes do not see them.
POWERSHELL_DELETE = frozenset({"remove-item", "ri", "rmdir", "rd"})
_PS_RECURSE = frozenset({"-recurse", "-r"})
_PS_PATH_OPTS = frozenset({"-path", "-literalpath", "-lp"})
# Options that take a value we should not read as a target.
_PS_VALUE_OPTS = frozenset({"-include", "-exclude", "-filter", "-stream"})


def _powershell_rm_hit(args: Sequence[str], cwd: Optional[str]) -> str:
    recursive = False
    targets: List[str] = []
    skip = False
    for i, a in enumerate(args):
        if skip:
            skip = False
            continue
        low = a.lower()
        if low in _PS_RECURSE:
            recursive = True
            continue
        if low in _PS_PATH_OPTS:
            continue                                   # the next word is the target
        if low in _PS_VALUE_OPTS:
            skip = True
            continue
        if a.startswith("-"):
            continue                                   # -Force, -Confirm:$false, ...
        targets.append(a)
    if not recursive:
        return ""
    for t in targets:
        if is_catastrophic(t, cwd):
            return f"recursive Remove-Item of {_trim(t)}"
    return ""


# ---------------------------------------------------------------- find | xargs rm

def _conn_op(text: str, simple: "shellparse.Simple") -> str:
    """The operator that joins this simple command to the next one (`|`, `&&`,
    `;` ...). The lexer sets `end` to the position just after that operator."""
    end = simple.end
    two = text[end - 2:end]
    if two in ("&&", "||", "|&", ";;"):
        return two
    one = text[end - 1:end]
    return one if one in ("|", ";", "&", "\n") else ""


def _find_starts(args: Sequence[str]) -> Tuple[List[str], List[str]]:
    """(start folders, the expression after them) for a find command's args,
    the same way _find_hit reads them."""
    i, starts = 0, []
    while i < len(args):
        a = args[i]
        if a in ("-H", "-L", "-P", "-E", "-X", "-d", "-s", "-x") or (a.startswith("-O") and a[2:].isdigit()):
            i += 1
        elif a == "-D" and i + 1 < len(args):
            i += 2
        elif a == "-f" and i + 1 < len(args):
            starts.append(args[i + 1])
            i += 2
        else:
            break
    while i < len(args) and not (args[i].startswith("-") and len(args[i]) > 1) \
            and args[i] not in ("(", "!", ",", ")", "\\(", "\\!"):
        starts.append(args[i])
        i += 1
    return (starts or ["."]), list(args[i:])


def _find_start_catastrophic(find_args: Sequence[str], cwd: Optional[str]) -> str:
    """The catastrophic start folder of a `find` whose output feeds a deleting
    xargs, or "". The home-folder narrowing exception (find ~ -name X) applies:
    a listing narrowed by name or path is a targeted cleanup."""
    starts, expr = _find_starts(find_args)
    home_ok = _find_narrowed(expr)
    for s in starts:
        if is_catastrophic(s, cwd, home_ok=home_ok):
            return _trim(s)
    return ""


def _pipe_deletes(words: Sequence[str], depth: int) -> bool:
    """The command on the receiving end of a pipe runs rm, unlink, shred or a
    recursive-capable permission change (xargs rm -rf, xargs -0 rm, | rm)."""
    return any(p in DELETE_PROGRAMS or p in PERM_PROGRAMS for p in _programs_of(words, depth))


# ---------------------------------------------------------------- library calls in code

# Recursive delete through a library, in inline code (python -c, node -e) or a
# script file: shutil.rmtree("/"), fs.rmSync("/", {recursive:true}),
# FileUtils.rm_rf("/"). The parsed shell rule never sees these.
_CODE_RMTREE_RE = re.compile(r"\b(?:shutil\.rmtree|os\.removedirs)\s*\(\s*([^,\n]+)")
_CODE_FS_RE = re.compile(
    r"(?:\bfs|require\(\s*['\"]fs['\"]\s*\))(?:\.promises)?\.(rmSync|rm|rmdirSync|rmdir)\s*\("
    r"\s*([^,\n]+?)\s*,\s*(\{[^}\n]*\})")
_CODE_FILEUTILS_RE = re.compile(r"\bFileUtils\.rm_r[f]?\s*\(\s*([^,\n]+)")
_CODE_SUBPROC_RE = re.compile(
    r"\b(?:subprocess\.(?:run|call|Popen|check_call|check_output)|os\.execv?p?e?|child_process\.\w+)\s*\(\s*\[([^\]]*)\]")
# The target argument is the home folder, spelled as a call rather than a string.
_CODE_HOME_RE = re.compile(
    r"^\s*(?:(?:pathlib\.)?Path\.home\s*\(\s*\)"
    r"|os\.path\.expanduser\s*\(\s*['\"]~['\"]\s*\)"
    r"|os\.getenv\s*\(\s*['\"](?:HOME|USERPROFILE)['\"]"
    r"|os\.environ(?:\.get)?\s*[\[(]\s*['\"](?:HOME|USERPROFILE)['\"]"
    r"|os\.homedir\s*\(\s*\)|require\(\s*['\"]os['\"]\s*\)\.homedir\s*\(\s*\)"
    r"|process\.env\.(?:HOME|USERPROFILE))")
_STRING_ITEM_RE = re.compile(r"""['"]([^'"]*)['"]""")


def _code_arg_catastrophic(arg: str) -> bool:
    """The first argument of a delete call names a catastrophic target: a
    string literal like "/" or "~", or a home-folder expression."""
    arg = arg.strip()
    if not arg:
        return False
    if arg[0] in "'\"":
        end = arg.find(arg[0], 1)
        return end > 0 and is_catastrophic(arg[1:end])
    return bool(_CODE_HOME_RE.match(arg))


def _shq(word: str) -> str:
    return "'" + word.replace("'", "'\\''") + "'" if re.search(r"\s", word) else word


def _code_hit(code: str) -> str:
    """A catastrophic delete expressed as a library call or an argument list in
    code (module doc: library calls). "" when none."""
    if not isinstance(code, str) or not code:
        return ""
    low = code.lower()
    # subprocess/child_process argument lists: rebuild the argv and read it as a
    # shell command (subprocess.run(["rm", "-rf", "/"])).
    if "[" in code and ("subprocess" in low or "execv" in low or "child_process" in low):
        for m in _CODE_SUBPROC_RE.finditer(code):
            items = _STRING_ITEM_RE.findall(m.group(1))
            if items:
                hit = _text_hit(" ".join(_shq(x) for x in items), MAX_DEPTH - 1, None)
                if hit:
                    return hit
    if "rmtree" in low or "removedirs" in low:
        for m in _CODE_RMTREE_RE.finditer(code):
            if _code_arg_catastrophic(m.group(1)):
                return f"recursive delete of {m.group(1).strip()[:60]} (catastrophic, irreversible): {code.strip()[:140]}"
    if "recursive" in low and ("rmsync" in low or "rmdirsync" in low or ".rm(" in low.replace(" ", "")):
        for m in _CODE_FS_RE.finditer(code):
            arg, opts = m.group(2), m.group(3)
            if "recursive" in opts.lower() and _code_arg_catastrophic(arg):
                return f"recursive delete of {arg.strip()[:60]} (catastrophic, irreversible): {code.strip()[:140]}"
    if "fileutils.rm_r" in low:
        for m in _CODE_FILEUTILS_RE.finditer(code):
            if _code_arg_catastrophic(m.group(1)):
                return f"recursive delete of {m.group(1).strip()[:60]} (catastrophic, irreversible): {code.strip()[:140]}"
    return ""


# ---------------------------------------------------------------- system control

# shutdown / reboot as the program (not as text a command prints or searches
# for). The old HARD_DENY_PATTERNS regexes matched `grep -rn shutdown src/` and
# `git commit -m "fix reboot handling"`; this reads the parsed program instead.
_SYSTEM_CONTROL = frozenset({"shutdown", "reboot", "restart-computer", "stop-computer"})


def system_control_hit(command: str) -> str:
    """A plain description when the command, or code it runs, runs shutdown,
    reboot or the PowerShell Stop-Computer / Restart-Computer; "" when not."""
    if not isinstance(command, str) or not command.strip():
        return ""
    low = command.lower()
    if not any(k in low for k in _SYSTEM_CONTROL):
        return ""
    texts = [command]
    try:
        texts += shellparse.extract_scripts(command)
    except Exception:
        pass
    for text in texts:
        try:
            simples = shellparse.split_commands(text)
        except Exception:
            continue
        for simple in simples:
            for words in _readings(simple):
                for p in _programs_of(words, 0):
                    if p in _SYSTEM_CONTROL:
                        return f"{p} (system shutdown/reboot): {_simple_text(simple)}"
    return ""


def code_hit(code: str) -> str:
    """Public: a catastrophic library-call delete in a code file (script_source)."""
    return _code_hit(code)


# ---------------------------------------------------------------- texts


def _simple_text(simple: "shellparse.Simple") -> str:
    text = " ".join(t.raw for t in simple.tokens)
    return text if len(text) <= 200 else text[:197] + "..."


def _text_hit(text: str, depth: int, cwd0: Optional[str] = None) -> str:
    try:
        simples = shellparse.split_commands(text)
    except Exception:
        return ""
    # find <catastrophic> | xargs rm -rf : the delete is on the far side of the
    # pipe, so no single simple command is a hit on its own.
    for i in range(len(simples) - 1):
        if _conn_op(text, simples[i]) not in ("|", "|&"):
            continue
        fargv, _ = _program_argv(_readings(simples[i])[0])
        if not fargv or _base(fargv[0]) != "find":
            continue
        if not _pipe_deletes(_readings(simples[i + 1])[0], depth):
            continue
        start = _find_start_catastrophic(fargv[1:], cwd0)
        if start:
            return (f"find {start} piped to a recursive delete (catastrophic, irreversible): "
                    f"{_simple_text(simples[i])} | {_simple_text(simples[i + 1])}")
    cwds: List[Optional[str]] = [cwd0, cwd0]           # one per reading
    for simple in simples:
        for r, words in enumerate(_readings(simple)):
            argv, extra = _program_argv(words)
            if depth < MAX_DEPTH:
                for code in extra:
                    hit = _all_hit(code, depth + 1, cwds[r])
                    if hit:
                        return hit
            if not argv:
                continue
            program, args, cwd = _base(argv[0]), argv[1:], cwds[r]
            if program in CD_PROGRAMS:
                cwds[r] = _cd_target(args, cwd)
                continue
            if program == "popd":
                cwds[r] = None
                continue
            if program == "rm":
                what = _rm_hit(args, cwd)
            elif program == "find":
                what = _find_hit(args, cwd, depth)
            elif program in PERM_PROGRAMS:
                what = _perm_hit(program, args, cwd)
            elif program in POWERSHELL_DELETE:
                what = _powershell_rm_hit(args, cwd)
            elif _is_var(argv[0]):
                # `$R -rf /`, `${RM} -rf /`: the program is a variable, but a
                # recursive flag with a literal catastrophic target is rm-like.
                what = _rm_hit(args, cwd)
            else:
                what = ""
            if what:
                return f"{what} (catastrophic, irreversible): {_simple_text(simple)}"
    return ""


def _all_hit(command: str, depth: int, cwd: Optional[str] = None) -> str:
    texts = [command]
    try:
        texts += shellparse.extract_scripts(command)
    except Exception:
        pass
    for text in texts:
        hit = _text_hit(text, depth, cwd) or _code_hit(text)
        if hit:
            return hit
    return ""


_RF_FLAG_RE = re.compile(r"(?:^|\s)-[A-Za-z]*r[A-Za-z]*f[A-Za-z]*(?:\s|$)"
                         r"|(?:^|\s)-[A-Za-z]*f[A-Za-z]*r[A-Za-z]*(?:\s|$)", re.IGNORECASE)
# A variable program (`$R`, `${RM}`, `$env:...`) next to a recursive-ish flag.
_VAR_FLAG_RE = re.compile(r"(?:^|\s)-[A-Za-z]*[rR][A-Za-z]*|--recursive|--force|--no-preserve-root", re.IGNORECASE)


def _mentions(command: str) -> bool:
    """A fast check to skip parsing: does the text plausibly hold a catastrophic
    program? Quotes and escape characters are removed first (`r''m`, `r\\m`,
    `ch^mod`). Broad on purpose: a false yes only costs one parse that finds
    nothing; a false no would miss a real hit."""
    flat = re.sub(r"[\"'\\^`$]", "", command).lower()
    if any(name in flat for name in _MENTION):
        return True
    if "remove-item" in flat or "removedirs" in flat or "rmtree" in flat:
        return True
    if "$'" in command:                                # ANSI-C quoting can hide the program name
        return True
    if "$" in command and _VAR_FLAG_RE.search(command):   # `$R -rf /`, `ri -Recurse $HOME`
        return True
    return bool(_RF_FLAG_RE.search(command))           # a recursive-force flag: rm-like


def catastrophic_hit(command: str, cwd: Optional[str] = None) -> str:
    """A plain description when the command, or code it runs, is a catastrophic
    delete or permission change (module doc); "" when not. cwd is the folder the
    command runs in, so `rm -rf *` counts when that folder is / or the home
    folder."""
    if not isinstance(command, str) or not command.strip() or not _mentions(command):
        return ""
    return _all_hit(command, 0, cwd)
