"""A deliberately small shell adapter for reversible Python cache cleanup.

This is not a safe-rm classifier. Only these exact root-cache operations are
implemented, by a fixed worker program that retains the entire directory.
Everything else continues through ordinary shell judgment and execution.
"""
from dataclasses import dataclass
import re


@dataclass(frozen=True)
class CacheCleanup:
    command: str
    status: bool


def parse(command: str) -> CacheCleanup | None:
    if not isinstance(command, str):
        return None
    text = command.strip(" \t")
    if not re.fullmatch(r"rm -(?:rf|fr) (?:-- )?__pycache__(?: && git status --short)?", text):
        return None
    return CacheCleanup(command, text.endswith(" && git status --short"))


# -I system Python, fixed source, no project imports, shell or user code. There
# is no unlink/rmtree: even unexpected contents are retained, without following
# child links. Directory descriptors pin the workspace and protected store.
# Rename is atomic and same-filesystem only; EXDEV never falls back to deletion.
PROGRAM = """
import os,stat,secrets,json
flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
root=os.open('/workspace',flags)
state=store=entry=None
try:
 state=os.open('.semgate',flags,dir_fd=root)
 try: os.mkdir('cache-recovery',0o700,dir_fd=state)
 except FileExistsError: pass
 store=os.open('cache-recovery',flags,dir_fd=state)
 try: source=os.stat('__pycache__',dir_fd=root,follow_symlinks=False)
 except FileNotFoundError:
  print(json.dumps({'cache_cleanup':{'path':'__pycache__','state':'absent'}}))
 else:
  if not stat.S_ISDIR(source.st_mode): raise ValueError('cache target must be a real directory')
  ident=secrets.token_hex(16)
  os.mkdir(ident,0o700,dir_fd=store)
  entry=os.open(ident,flags,dir_fd=store)
  # Persist the recovery manifest BEFORE moving. A crash cannot lose the
  # original location or run a destructive fallback; empty entries are benign.
  fd=os.open('manifest.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=entry)
  with os.fdopen(fd,'w') as stream:
   json.dump({'version':1,'original_path':'__pycache__','recovery_id':ident},stream)
   stream.flush(); os.fsync(stream.fileno())
  os.fsync(entry)
  os.rename('__pycache__','tree',src_dir_fd=root,dst_dir_fd=entry)
  os.fsync(entry); os.fsync(root)
  print(json.dumps({'cache_cleanup':{'path':'__pycache__','state':'retained','recovery_id':ident}}))
finally:
 for fd in (entry,store,state,root):
  if fd is not None: os.close(fd)
"""
