"""Pinned source for an isolated Python invocation in a read-only offline view.

This is an execution contract, not an agent-asserted permission or an AST safety
classifier. Normal gates and semantic scores still decide whether it may run.
"""
from dataclasses import dataclass
import hashlib
import re
import shlex
import ast
from urllib.parse import urlsplit

MAX_SOURCE = 8192


def network_probe_eligible(source: str) -> bool:
    """A closed HTTP-client subset, not a general Python safety decision.

    No project imports, file URLs/opens, reflection, definitions, dynamic
    calls, mutation of imported APIs or hidden control-flow scopes. The
    kernel boundary still enforces offline/read-only effects at execution.
    Unsupported source keeps the original network gate.
    """
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return False
    modules = {"urllib.request", "urllib.error", "http.client", "socket"}
    functions = {"urllib.request.Request", "urllib.request.urlopen", "http.client.HTTPConnection",
                 "http.client.HTTPSConnection", "socket.create_connection"}
    keywords = {"urllib.request.Request": {"data", "headers", "method", "origin_req_host", "unverifiable"},
                "urllib.request.urlopen": {"data", "timeout"},
                "http.client.HTTPConnection": {"host", "port", "timeout", "source_address", "blocksize"},
                "http.client.HTTPSConnection": {"host", "port", "timeout", "source_address", "blocksize"},
                "socket.create_connection": {"timeout", "source_address", "all_errors"}}
    builtins = {"print", "str", "repr", "type", "SystemExit", "len"}
    methods = {"request", "getresponse", "read", "decode", "encode", "close", "getcode", "send", "sendall", "recv"}
    allowed = (ast.Module, ast.Import, ast.ImportFrom, ast.alias, ast.Assign, ast.Name, ast.Load, ast.Store,
               ast.Attribute, ast.Call, ast.keyword, ast.Constant, ast.Dict, ast.List, ast.Tuple,
               ast.Expr, ast.Try, ast.ExceptHandler, ast.With, ast.withitem, ast.Raise, ast.Pass,
               ast.JoinedStr, ast.FormattedValue, ast.BinOp, ast.Add, ast.UnaryOp, ast.USub)
    aliases = {}; bindings = {}
    nodes = list(ast.walk(tree))
    if len(nodes) > 512 or any(not isinstance(n, allowed) for n in nodes):
        return False
    for node in nodes:
        if isinstance(node, ast.Import):
            for item in node.names:
                if item.name not in modules: return False
                aliases[item.asname or item.name.split('.')[0]] = item.name if item.asname else item.name.split('.')[0]
        elif isinstance(node, ast.ImportFrom):
            if node.level or node.module not in {"urllib", "urllib.request", "urllib.error", "http", "http.client"}: return False
            for item in node.names:
                target = node.module + '.' + item.name
                if target not in modules | functions | {"urllib.error.URLError", "urllib.error.HTTPError", "http.client.HTTPException"}: return False
                aliases[item.asname or item.name] = target
        elif isinstance(node, ast.Assign):
            if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name): return False
            bindings.setdefault(node.targets[0].id, []).append(node.value)
    protected = set(aliases) | builtins
    if any(isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store) and n.id in protected for n in nodes): return False
    if any(isinstance(n, ast.ExceptHandler) and n.name in protected for n in nodes): return False
    def name(node):
        if isinstance(node, ast.Name): return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute): return name(node.value) + '.' + node.attr
        return ''
    def imported_root(node):
        while isinstance(node, ast.Attribute): node = node.value
        return isinstance(node, ast.Name) and node.id in aliases
    references = modules | functions | {"urllib", "http", "urllib.error.URLError", "urllib.error.HTTPError", "http.client.HTTPException"}
    for node in nodes:
        if isinstance(node, ast.Assign) and imported_root(node.value): return False
        if isinstance(node, ast.Attribute) and imported_root(node) and name(node) not in references: return False
    def literal_url(node, seen=()):
        if isinstance(node, ast.Name) and node.id not in seen and len(bindings.get(node.id, [])) == 1:
            return literal_url(bindings[node.id][0], seen + (node.id,))
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str): return False
        try:
            url = urlsplit(node.value)
            return url.scheme in {"http", "https"} and bool(url.hostname) and url.username is None and url.password is None
        except ValueError: return False
    def request(node, seen=()):
        if isinstance(node, ast.Name) and node.id not in seen and len(bindings.get(node.id, [])) == 1:
            return request(bindings[node.id][0], seen + (node.id,))
        return (isinstance(node, ast.Call) and name(node.func) == "urllib.request.Request"
                and bool(node.args) and literal_url(node.args[0]))
    network = False
    for node in nodes:
        if isinstance(node, ast.Attribute) and node.attr.startswith('_'):
            if node.attr != '__name__' or not isinstance(node.value, ast.Call) or name(node.value.func) != 'type': return False
        if not isinstance(node, ast.Call): continue
        if any(isinstance(a, ast.Starred) for a in node.args) or any(k.arg is None for k in node.keywords): return False
        target = name(node.func)
        if target in functions:
            network = True
            if len(node.args) > 2 or any(k.arg not in keywords[target] for k in node.keywords): return False
            if target == 'urllib.request.Request' and (not node.args or not literal_url(node.args[0])): return False
            if target == 'urllib.request.urlopen' and (not node.args or not (literal_url(node.args[0]) or request(node.args[0]))): return False
        elif isinstance(node.func, ast.Name) and target in builtins:
            if target == 'type' and (len(node.args) != 1 or node.keywords): return False
        elif isinstance(node.func, ast.Attribute) and node.func.attr in methods:
            pass
        else: return False
    return network


def invocation(command: str) -> str | None:
    if not isinstance(command, str) or any(c in command for c in "\r\n\0"):
        return None
    try:
        words = shlex.split(command)
    except ValueError:
        return None
    if (not 2 <= len(words) <= 4 or words[0] not in {"python3", "/usr/bin/python3"}
            or any(flag not in {"-I", "-B"} for flag in words[1:-1])
            or len(set(words[1:-1])) != len(words[1:-1])):
        return None
    path = words[-1]
    if path.startswith("./"):
        path = path[2:]
    if (not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_./-]{0,511}\.py", path)
            or any(p in {"", ".", ".."} or p.casefold() in {".semgate", ".codex", ".agents", ".git", ".venv"}
                   for p in path.split("/"))):
        return None
    return path


@dataclass(frozen=True)
class ScriptSnapshot:
    command: str
    path: str
    source: str
    sha256: str

    def __post_init__(self):
        if invocation(self.command) != self.path or not isinstance(self.source, str):
            raise ValueError("invalid isolated script invocation")
        data = self.source.encode("utf-8")
        if not data or len(data) > MAX_SOURCE or b"\0" in data or hashlib.sha256(data).hexdigest() != self.sha256:
            raise ValueError("invalid isolated script snapshot")

    def payload(self) -> dict:
        return {"command": self.command, "path": self.path, "source": self.source, "sha256": self.sha256}

    @classmethod
    def from_payload(cls, value):
        if not isinstance(value, dict) or set(value) != {"command", "path", "source", "sha256"}:
            raise ValueError("invalid isolated script fields")
        return cls(**value)


# Fixed inspector, run before judgment with a read-only project mount. Refuse
# links, devices, FIFOs and oversized sources; never import or execute the file.
INSPECT = """
import os,sys,stat,base64,json
directory=os.open('/workspace',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
 parts=sys.argv[1].split('/')
 for part in parts[:-1]:
  child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory)
  os.close(directory); directory=child
 fd=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
 with os.fdopen(fd,'rb') as stream:
  if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode): raise ValueError('not a regular source')
  data=stream.read(8193)
 if not data or len(data)>8192: raise ValueError('source size limit')
 print(json.dumps({'source_base64':base64.b64encode(data).decode('ascii')}))
finally: os.close(directory)
"""
