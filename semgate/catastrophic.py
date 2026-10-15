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
- a recursive delete through a library call, in inline code or a script file:
  Python (`shutil.rmtree("/")`, `os.removedirs("/")`, `subprocess.run(["rm","-rf","/"])`),
  Node (`fs.rmSync("/", {recursive:true})`, `rimraf("/")`, `del(["/"])`),
  Ruby (`FileUtils.rm_rf("/")`), Deno (`Deno.removeSync("/", {recursive:true})`),
  Perl (`rmtree("/")`, `remove_tree("/")`) and Go (`os.RemoveAll("/")`), with the
  target given as "/", "~", `Path.home()`, `os.path.expanduser("~")`,
  `process.env.HOME` or wrapped in `Path::new("/")` / `new File("/")`.
  Reached inline (`python -c`, `node -e`, `deno eval`, `perl -e`) and in the
  files semgate reads (.py .js .rb .sh .pl, and .go through `go run x.go`).
  Rust, Java and .NET are NOT covered: they have no inline eval and no
  single-command run-from-source semgate parses, so a literal-shape rule for
  them would be dead code; those fall to the judge / human gate instead;
- ANSI-C escapes in the program word (`$'\\x72m' -rf /`);
- PowerShell `Remove-Item -Recurse` of / or the home folder;
- `rm -rf *` when the folder the command runs in (cwd) is / or the home folder.

Still only a human gate (ask): the target itself in a variable (`rm -rf "$DIR/"`,
`rm -rf "$DIR"/*`) - a legitimate build script writes this with $DIR set, so a
hard deny would block real work; the ask still catches the empty-variable wipe.

outside_project_hit is the sibling rule (default-on, also before the judge): a
destructive command whose target is OUTSIDE the project folder is a hard deny,
so "clean node_modules" cannot delete the global one. The catastrophic rule
above denies a target that is a root or the home folder in the absolute; this
rule denies a target outside the box the agent was given. It covers deletes
(rm, unlink, del, find -delete, the library deletes, Remove-Item), moves and
copies (mv, cp: the destination), and a truncating `>` redirect; an append
`>>` and every read are left alone. The boundary is project_root, then cwd;
the scratch and cache folders real dev touches are allowed (/tmp, $TMPDIR,
~/.cache, ~/.npm, ~/.cargo, ...). It uses _scope_resolve, where a bare `/p` is
an ordinary folder, not the C: drive.
"""
from __future__ import annotations

import fnmatch
import os
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


def _resolve(word: str, cwd: Optional[str], bare_drive: bool = True) -> Optional[str]:
    """The absolute path a target word names, with the home folder at HOME
    and a Windows drive at /mnt/<letter>. None when it depends on a folder
    that is not known (a relative path with no known cwd, ~-).

    bare_drive maps a bare `/c` to the C: drive (Git Bash), which the
    catastrophic check wants (`rm -rf /c` is a drive wipe). The project-scope
    check passes bare_drive=False: there `/p` is an ordinary folder (a project
    root), not a drive, and the boundary and the targets must resolve the same
    way or an in-project path looks outside."""
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
    drive = re.match(r"^([A-Za-z]):(/.*)?$", w) or re.match(r"^/cygdrive/([A-Za-z])(/.*)?$", w, re.IGNORECASE)
    if drive is None and bare_drive:
        drive = re.match(r"^/([A-Za-z])(/.*)?$", w)
    if drive:
        w = "/mnt/" + drive.group(1).lower() + (drive.group(2) or "")
    if not w.startswith("/"):
        if cwd is None:
            return None
        # The cwd may be a Windows drive path (C:\Users\<name>, C:/Users/<name>):
        # resolve it the same way, so `rm -rf *` run from the home folder is
        # seen. A bare `/c/...` cwd is left as written: `/p` (a project root)
        # is a directory, not the C: drive, and a false hard deny is worse.
        base = _resolve(cwd, None, bare_drive) if (re.match(r"^[A-Za-z]:", cwd) or "\\" in cwd) else cwd
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


def _scope_resolve(word: str, cwd: Optional[str]) -> Optional[str]:
    """_resolve for the project-scope check: a bare `/p` stays `/p`, so the
    boundary and the targets are in one space."""
    return _resolve(word, cwd, bare_drive=False)


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
_STRING_ITEM_RE = re.compile(r"""['"]([^'"]*)['"]""")
# Recursive-delete calls that are always recursive and take the target as their
# first argument: (compiled regex with the target in group 1, a cheap substring
# that must be in the code before the regex runs). One per language / library.
_CODE_SIMPLE = (
    (re.compile(r"\b(?:shutil\.rmtree|os\.removedirs)\s*\(\s*([^,\n]+)"), "rmtree", "removedirs"),  # Python
    (re.compile(r"\bFileUtils\.rm_r[f]?\s*\(\s*([^,\n]+)"), "fileutils.rm_r"),                       # Ruby
    (re.compile(r"\bos\.RemoveAll\s*\(\s*([^,)\n]+)"), "removeall"),                                 # Go (go run x.go)
    (re.compile(r"\b(?:File::Path::)?(?:rmtree|remove_tree)\s*\(\s*([^,)\n;]+)"), "rmtree", "remove_tree"),  # Perl
    (re.compile(r"\b(?:rimraf|require\(\s*['\"]rimraf['\"]\s*\))(?:\.sync)?\s*\(\s*([^,)\n]+)"), "rimraf"),   # npm rimraf
)
# Recursive only with an options object that says so (Node fs, Deno). group 1 is
# the target, group 2 the options object.
_CODE_OPTS = (
    (re.compile(r"(?:\bfs|require\(\s*['\"]fs['\"]\s*\))(?:\.promises)?\.(?:rmSync|rm|rmdirSync|rmdir)\s*\("
                r"\s*([^,\n]+?)\s*,\s*(\{[^}\n]*\})"), "rmsync", "rmdirsync", ".rm(", "fs.promises"),  # Node fs
    (re.compile(r"\bDeno\.(?:remove|removeSync)\s*\(\s*([^,\n]+?)\s*,\s*(\{[^}\n]*\})"), "deno.remove"),  # Deno
)
_CODE_DEL_RE = re.compile(r"\bdel(?:\.sync)?\s*\(\s*\[([^\]]*)\]")                                    # npm del (globs)
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
_CODE_LITERAL_RE = re.compile(r"""(['"`])(.*?)\1""")


def _code_arg_path(arg: str) -> Optional[str]:
    """The path a delete call's first argument names: a string literal (single,
    double or backtick quotes), "~" for a home-folder expression, or the literal
    wrapped in a path constructor (Path::new("/"), new File("/")). None when the
    argument is a variable or otherwise not a literal."""
    arg = arg.strip()
    if not arg:
        return None
    if arg[0] in "'\"`":
        end = arg.find(arg[0], 1)
        return arg[1:end] if end > 0 else None
    if _CODE_HOME_RE.match(arg):
        return "~"
    m = _CODE_LITERAL_RE.search(arg)
    return m.group(2) if m else None


def _code_arg_catastrophic(arg: str) -> bool:
    """True when the delete call's first argument names a catastrophic target
    (a root or the home folder)."""
    p = _code_arg_path(arg)
    return bool(p) and is_catastrophic(p)


def _shq(word: str) -> str:
    return "'" + word.replace("'", "'\\''") + "'" if re.search(r"\s", word) else word


def _report(target: str, code: str) -> str:
    return f"recursive delete of {target.strip()[:60]} (catastrophic, irreversible): {code.strip()[:140]}"


def _code_hit(code: str) -> str:
    """A catastrophic delete expressed as a library call or an argument list in
    code (module doc: library calls), in Python, Node, Ruby, Go, Rust, Perl,
    Java or .NET. "" when none."""
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
    for pattern, *guards in _CODE_SIMPLE:
        if any(g in low for g in guards):
            for m in pattern.finditer(code):
                if _code_arg_catastrophic(m.group(1)):
                    return _report(m.group(1), code)
    for pattern, *guards in _CODE_OPTS:
        if any(g in low for g in guards):
            for m in pattern.finditer(code):
                if "recursive" in m.group(2).lower() and _code_arg_catastrophic(m.group(1)):
                    return _report(m.group(1), code)
    if "del(" in low.replace(" ", "") or "del.sync(" in low.replace(" ", ""):
        for m in _CODE_DEL_RE.finditer(code):                      # npm del(['/']) deletes matched paths
            for item in _STRING_ITEM_RE.findall(m.group(1)):
                if is_catastrophic(item):
                    return _report(item, code)
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
# Library-delete names whose text does not contain an rm/find/chmod word, so the
# _MENTION check above misses them (deno eval, node -e rimraf, a Go/Rust file).
_LIB_MENTIONS = ("remove-item", "removedirs", "rmtree", "removeall", "remove_tree",
                 "rimraf", "removesync", "deno.remove")


def _mentions(command: str) -> bool:
    """A fast check to skip parsing: does the text plausibly hold a catastrophic
    program or a library-delete call? Quotes and escape characters are removed
    first (`r''m`, `r\\m`, `ch^mod`). Broad on purpose: a false yes only costs
    one parse that finds nothing; a false no would miss a real hit."""
    flat = re.sub(r"[\"'\\^`$]", "", command).lower()
    if any(name in flat for name in _MENTION):
        return True
    if any(name in flat for name in _LIB_MENTIONS):
        return True
    if "del([" in flat.replace(" ", "") or "del.sync([" in flat.replace(" ", ""):   # npm del(['/'])
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


# ---------------------------------------------------------------- outside the project

# A destructive command whose target is outside the project folder is a hard
# deny by default: a tired person could approve "clean node_modules" that turns
# out to delete the global one. This is the catastrophic floor's sibling - the
# catastrophic rule denies a target that is a root or the home folder in the
# absolute; this rule denies a target outside the box the agent was given, with
# an allowlist for the scratch and cache folders real dev work touches. Deletes,
# moves, copies over a file, and a truncating `>` redirect count; reads never do.

# Scratch folders a destructive op may touch outside the project.
_SCRATCH_DIRS = ("/tmp", "/var/tmp", "/private/tmp", "/private/var/tmp", "/dev/shm")
# Package / build caches under the home folder (resolved to /home/~/<name>).
_HOME_CACHE = (".cache", ".npm", ".yarn", ".pnpm-store", ".gradle", ".m2", ".cargo", ".rustup",
               ".gem", ".nuget", ".ivy2", ".composer", ".local/share/virtualenvs", ".local/share/pnpm")

_DELETE_CMDS = DELETE_PROGRAMS | {"del", "erase"}
_MOVE_CMDS = frozenset({"mv", "move", "move-item", "mi"})
_COPY_CMDS = frozenset({"cp", "copy", "copy-item", "cpi"})
_TRUNC_RE = re.compile(r"^\d*>\|?$")                    # >  1>  2>  >|  (not >>, not >&)
_DESTRUCTIVE_WORDS = ("rm", "unlink", "shred", "del", "erase", "mv", "move", "cp", "copy",
                      "remove-item", "find", "removeall", "rmtree", "remove_tree", "rimraf", "removesync")


def _plain_targets(args: Sequence[str]) -> List[str]:
    """Non-option words of a delete command (rm, unlink, del ...), option
    parsing stopping at `--`."""
    done, targets = False, []
    for a in args:
        if not done and a == "--":
            done = True
            continue
        if not done and a.startswith("-") and len(a) > 1:
            continue
        targets.append(a)
    return targets


def _powershell_targets(args: Sequence[str]) -> List[str]:
    targets, skip = [], False
    for a in args:
        if skip:
            skip = False
            continue
        low = a.lower()
        if low in _PS_RECURSE or low in _PS_PATH_OPTS:
            continue
        if low in _PS_VALUE_OPTS:
            skip = True
            continue
        if a.startswith("-"):
            continue
        targets.append(a)
    return targets


def _mv_cp_dest(args: Sequence[str]) -> List[str]:
    for i, a in enumerate(args):
        if a in ("-t", "--target-directory") and i + 1 < len(args):
            return [args[i + 1]]
        if a.startswith("--target-directory="):
            return [a.split("=", 1)[1]]
    non = [a for a in args if not (a.startswith("-") and len(a) > 1)]
    return non[-1:] if non else []                      # the destination is the last operand


def _find_deletes(expr: Sequence[str], depth: int) -> bool:
    if "-delete" in expr:
        return True
    for k, e in enumerate(expr):
        if e in ("-exec", "-execdir", "-ok", "-okdir"):
            body = []
            for w in expr[k + 1:]:
                if w in (";", "\\;", "+"):
                    break
                body.append(w)
            if any(p in DELETE_PROGRAMS or p in _MOVE_CMDS or p in _COPY_CMDS for p in _programs_of(body, depth)):
                return True
    return False


def _op_target_words(prog: str, argv: Sequence[str], args: Sequence[str], depth: int) -> List[Tuple[str, str]]:
    if prog in _DELETE_CMDS:
        return [(w, "delete") for w in _plain_targets(args)]
    if prog in POWERSHELL_DELETE:
        return [(w, "delete") for w in _powershell_targets(args)]
    if prog in _MOVE_CMDS:
        return [(w, "move") for w in _mv_cp_dest(args)]
    if prog in _COPY_CMDS:
        return [(w, "overwrite") for w in _mv_cp_dest(args)]
    if prog == "find":
        starts, expr = _find_starts(args)
        return [(w, "find delete") for w in starts] if _find_deletes(expr, depth) else []
    return []


def _truncate_redirect_targets(simple: "shellparse.Simple") -> List[str]:
    toks = simple.tokens
    out = []
    for i, t in enumerate(toks):
        if t.redirect and _TRUNC_RE.match(t.raw) and i + 1 < len(toks) and not toks[i + 1].redirect:
            out.append(toks[i + 1].value)
    return out


def _destructive_targets(text: str, cwd: Optional[str]) -> List[Tuple[str, str]]:
    """(resolved absolute target, op label) for each destructive operation the
    shell text performs: deletes, moves, copies over a file, truncating `>`."""
    results: List[Tuple[str, str]] = []
    try:
        simples = shellparse.split_commands(text)
    except Exception:
        return results
    cwds: List[Optional[str]] = [cwd, cwd]
    for simple in simples:
        redirs = _truncate_redirect_targets(simple)
        for r, words in enumerate(_readings(simple)):
            argv, _ = _program_argv(words)
            c = cwds[r]
            if argv:
                prog, args = _base(argv[0]), argv[1:]
                if prog in CD_PROGRAMS:
                    cwds[r] = _cd_target(args, c)
                    continue
                if prog == "popd":
                    cwds[r] = None
                    continue
                for w, label in _op_target_words(prog, argv, args, 0):
                    for e in _expand_braces(_trim(w)):
                        p = _scope_resolve(e, c)
                        if p:
                            results.append((p, label))
            if r == 0:
                for w in redirs:
                    p = _scope_resolve(w, c)
                    if p:
                        results.append((p, "overwrite"))
    return results


def _code_destructive_targets(code: str, cwd: Optional[str]) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    if not isinstance(code, str) or not code:
        return out
    low = code.lower()
    for pattern, *guards in _CODE_SIMPLE:
        if any(g in low for g in guards):
            for m in pattern.finditer(code):
                p = _code_arg_path(m.group(1))
                if p is not None:
                    r = _scope_resolve(p, cwd)
                    if r:
                        out.append((r, "delete (code)"))
    for pattern, *guards in _CODE_OPTS:
        if any(g in low for g in guards):
            for m in pattern.finditer(code):
                if "recursive" in m.group(2).lower():
                    p = _code_arg_path(m.group(1))
                    if p is not None:
                        r = _scope_resolve(p, cwd)
                        if r:
                            out.append((r, "delete (code)"))
    if "del([" in low.replace(" ", "") or "del.sync([" in low.replace(" ", ""):
        for m in _CODE_DEL_RE.finditer(code):
            for item in _STRING_ITEM_RE.findall(m.group(1)):
                r = _scope_resolve(item, cwd)
                if r:
                    out.append((r, "delete (code)"))
    if "[" in code and ("subprocess" in low or "execv" in low or "child_process" in low):
        for m in _CODE_SUBPROC_RE.finditer(code):
            items = _STRING_ITEM_RE.findall(m.group(1))
            if items:
                out += _destructive_targets(" ".join(_shq(x) for x in items), cwd)
    return out


def _norm_root(path: str) -> Optional[str]:
    return _scope_resolve(path, None)


def _default_allowed_roots(project_root: Optional[str], cwd: Optional[str]) -> List[str]:
    roots: List[str] = []
    for b in (project_root, cwd):
        if b:
            r = _norm_root(b)
            if r:
                roots.append(r)
    roots += list(_SCRATCH_DIRS)
    for var in ("TMPDIR", "TEMP", "TMP"):
        v = os.environ.get(var)
        if v:
            r = _norm_root(v)
            if r:
                roots.append(r)
    for c in _HOME_CACHE:
        r = _norm_root("~/" + c)
        if r:
            roots.append(r)
    return roots


def _under(path: str, roots: Sequence[str]) -> bool:
    for r in roots:
        rr = r.rstrip("/")
        if rr and (path == rr or path.startswith(rr + "/")):
            return True
    return False


def _display(p: str) -> str:
    if p == HOME or p.startswith(HOME + "/"):
        return "~" + p[len(HOME):]
    m = re.match(r"^/mnt/([a-z])(/.*)?$", p)
    if m:
        return m.group(1).upper() + ":" + (m.group(2) or "/")
    return p


def outside_project_hit(command: str, cwd: Optional[str] = None, project_root: Optional[str] = None,
                        allow_dirs: Sequence[str] = ()) -> str:
    """A plain description when the command deletes, moves, copies over or
    truncates a file outside the project folder (and outside the scratch/cache
    allowlist); "" when not, or when no project folder is known. cwd resolves
    relative targets; project_root (or cwd) is the boundary."""
    if not isinstance(command, str) or not command.strip():
        return ""
    if not (project_root or cwd):
        return ""
    low = command.lower()
    if not (">" in command or any(w in low for w in _DESTRUCTIVE_WORDS)
            or any(g in low for g in _LIB_MENTIONS)):
        return ""
    rcwd = cwd or project_root
    roots = _default_allowed_roots(project_root, cwd)
    for d in allow_dirs:
        if d:
            r = _norm_root(d)
            if r:
                roots.append(r)
    texts = [command]
    try:
        texts += shellparse.extract_scripts(command)
    except Exception:
        pass
    for text in texts:
        for p, label in _destructive_targets(text, rcwd) + _code_destructive_targets(text, rcwd):
            if not _under(p, roots):
                return f"{label} of {_display(p)} outside the project folder"
    return ""
