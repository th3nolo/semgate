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

Not seen here: the program or a target in a variable (`R=rm; $R -rf /`,
`rm -rf "$DIR/"` with DIR empty), a target list from a pipe
(`find / | xargs rm -rf`), deletes through a library call
(`shutil.rmtree("/")`, `subprocess.run(["rm", "-rf", "/"])`), ANSI-C escapes
(`$'\\x72m'`), and PowerShell Remove-Item of the home folder. The human gates
still ask for those.
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


def _unquote(raw: str) -> str:
    """A word as written, without its outer quotes ($'...' too). A Windows
    path keeps its backslashes: cmd and PowerShell do not treat them as
    escapes."""
    if len(raw) > 2 and raw[0] == "$" and raw[1] in "'\"":
        raw = raw[1:]
    if len(raw) > 1 and raw[0] == raw[-1] and raw[0] in "\"'":
        return raw[1:-1]
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
        w = cwd + "/" + w
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


# ---------------------------------------------------------------- texts


def _simple_text(simple: "shellparse.Simple") -> str:
    text = " ".join(t.raw for t in simple.tokens)
    return text if len(text) <= 200 else text[:197] + "..."


def _text_hit(text: str, depth: int) -> str:
    try:
        simples = shellparse.split_commands(text)
    except Exception:
        return ""
    cwds: List[Optional[str]] = [None, None]          # one per reading
    for simple in simples:
        for r, words in enumerate(_readings(simple)):
            argv, extra = _program_argv(words)
            if depth < MAX_DEPTH:
                for code in extra:
                    hit = _all_hit(code, depth + 1)
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
            else:
                what = ""
            if what:
                return f"{what} (catastrophic, irreversible): {_simple_text(simple)}"
    return ""


def _all_hit(command: str, depth: int) -> str:
    texts = [command]
    try:
        texts += shellparse.extract_scripts(command)
    except Exception:
        pass
    for text in texts:
        hit = _text_hit(text, depth)
        if hit:
            return hit
    return ""


def _mentions(command: str) -> bool:
    """A fast check: one of the program names is in the text once quotes and
    escape characters are removed (`r''m`, `r\\m`, `ch^mod`)."""
    flat = re.sub(r"[\"'\\^`$]", "", command).lower()
    return any(name in flat for name in _MENTION)


def catastrophic_hit(command: str) -> str:
    """A plain description when the command, or code it runs, is a
    catastrophic delete or permission change (module doc); "" when not."""
    if not isinstance(command, str) or not command.strip() or not _mentions(command):
        return ""
    return _all_hit(command, 0)
