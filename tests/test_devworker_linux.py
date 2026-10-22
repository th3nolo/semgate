"""Optional real-kernel checks; also runnable with stdlib Python in WSL.

python3 -I tests/test_devworker_linux.py
No Semgate SDK, mock sandbox, package install or privileged setup is used.
"""
import http.server
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

spec = importlib.util.spec_from_file_location("standalone_devworker", Path(__file__).resolve().parents[1]/"semgate/devworker.py")
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


def supported_launcher():
    if sys.platform != "linux":
        return False
    try:
        text = subprocess.check_output([os.environ.get("SEMGATE_TEST_BWRAP", "/usr/bin/bwrap"), "--version"], text=True, timeout=5)
        return tuple(map(int, text.split()[1].split('.'))) >= (0,12,0)
    except (OSError, ValueError, subprocess.SubprocessError):
        return False


@unittest.skipUnless(supported_launcher(), "requires existing Linux bubblewrap >=0.12.0")
class TestOfflineBoundary(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="semgate-offline-test-")
        self.root = Path(self.temp.name)
        (self.root/".semgate").mkdir()
        (self.root/".semgate/operator-canary").write_text("synthetic operator state")

    def tearDown(self):
        self.temp.cleanup()

    def run_job(self, command, timeout=5):
        return worker.execute({"project":str(self.root), "command":command,
            "timeout_s":timeout, "tools":{"uv":os.environ["SEMGATE_TEST_UV"]} if os.environ.get("SEMGATE_TEST_UV") else {}, "protected":[],
            "bubblewrap":os.environ.get("SEMGATE_TEST_BWRAP", "/usr/bin/bwrap"),
            "bubblewrap_sha256":os.environ.get("SEMGATE_TEST_BWRAP_SHA256")})

    def test_old_or_replaced_launcher_is_refused_before_execution(self):
        payload={"project":str(self.root), "command":"touch must-not-exist", "timeout_s":5,
                 "tools":{}, "protected":[], "bubblewrap":"/usr/bin/bwrap"}
        system = subprocess.check_output(["/usr/bin/bwrap", "--version"], text=True)
        if tuple(map(int, system.split()[1].split('.'))) < (0,12,0):
            with self.assertRaisesRegex(ValueError, "0.12.0"):
                worker.execute(payload)
        payload["bubblewrap"] = os.environ.get("SEMGATE_TEST_BWRAP", "/usr/bin/bwrap")
        payload["bubblewrap_sha256"] = "0"*64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            worker.execute(payload)
        self.assertFalse((self.root/"must-not-exist").exists())

    def test_preflight_uses_real_kernel_boundary_before_reporting_facts(self):
        instance = worker.OfflineWorker({"backend":"bubblewrap", "timeout_s":5,
            "bubblewrap":os.environ.get("SEMGATE_TEST_BWRAP", "/usr/bin/bwrap"),
            "bubblewrap_sha256":os.environ.get("SEMGATE_TEST_BWRAP_SHA256")})
        try:
            facts = instance.verify(str(self.root), protected=(str(self.root/".semgate/operator-canary"),))
            self.assertGreaterEqual(tuple(map(int, facts.launcher_version.split('.'))), (0,12,0))
            self.assertEqual(len(facts.launcher_sha256),64)
            self.assertIn("trusted broker", facts.render())
            self.assertEqual(sorted(p.name for p in self.root.iterdir()), [".semgate"])
        finally:
            instance.close()

    def isolated_script(self,source):
        import hashlib
        snap=worker.readonlyscript.ScriptSnapshot('python3 probe.py','probe.py',source,hashlib.sha256(source.encode()).hexdigest())
        result=worker.execute({'project':str(self.root),'script_snapshot':snap.payload(),
            'timeout_s':5,'tools':{},'protected':[],
            'bubblewrap':os.environ.get('SEMGATE_TEST_BWRAP','/usr/bin/bwrap'),
            'bubblewrap_sha256':os.environ.get('SEMGATE_TEST_BWRAP_SHA256')})
        self.assertEqual(result['script_snapshot']['sha256'],snap.sha256)
        return result

    def test_isolated_pinned_probe_attempts_real_http_but_cannot_reach_host(self):
        from urllib.request import Request,urlopen
        arrivals=[]
        class Sink(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                arrivals.append(self.rfile.read(int(self.headers['Content-Length'])))
                self.send_response(204);self.end_headers()
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Sink)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        url=f'http://127.0.0.1:{server.server_port}/canary'
        try:
            with urlopen(Request(url,data=b'CONTROL'),timeout=2) as response:self.assertEqual(response.status,204)
            source=f"import urllib.request\nrequest=urllib.request.Request({url!r},data=b'PROBE')\nurllib.request.urlopen(request,timeout=1)\n"
            result=self.isolated_script(source)
            self.assertNotEqual(result['exit_code'],0,result)
            self.assertIn('Connection refused',result['stderr'])
            self.assertEqual(arrivals,[b'CONTROL'])
        finally:server.shutdown();server.server_close();thread.join(2)

    def test_pinned_script_ignores_file_mutation_and_project_import_shadow(self):
        (self.root/'probe.py').write_text("raise AssertionError('changed script executed')\n")
        (self.root/'urllib.py').write_text("raise AssertionError('project module imported')\n")
        result=self.isolated_script("import urllib.request\nprint('PINNED_STDLIB_SOURCE')\n")
        self.assertEqual(result['exit_code'],0,result)
        self.assertIn('PINNED_STDLIB_SOURCE',result['stdout'])
        self.assertIn('changed script', (self.root/'probe.py').read_text())

    def test_isolated_script_cannot_change_project_snapshot_or_operator_state(self):
        (self.root/'keep.txt').write_text('original')
        source="""from pathlib import Path
import os,subprocess
assert not list(Path('.semgate').iterdir())
for target in ('keep.txt','new.txt','/semgate-reviewed.py'):
 try: Path(target).write_text('changed')
 except OSError: pass
 else: raise AssertionError('persistent write succeeded')
try: os.unlink('keep.txt')
except OSError: pass
else: raise AssertionError('persistent delete succeeded')
child=subprocess.run(['/usr/bin/python3','-I','-c',"open('/workspace/keep.txt','w').write('child')"],capture_output=True)
assert child.returncode != 0
Path('/tmp/guest-file').write_text('temporary')
print('PROJECT_AND_SOURCE_READ_ONLY')
"""
        result=self.isolated_script(source)
        self.assertEqual(result['exit_code'],0,result)
        self.assertEqual((self.root/'keep.txt').read_text(),'original')
        self.assertFalse((self.root/'new.txt').exists())
        self.assertEqual((self.root/'.semgate/operator-canary').read_text(),'synthetic operator state')

    def test_fixed_source_inspector_refuses_links_and_captures_exact_bytes(self):
        instance=worker.OfflineWorker({'backend':'bubblewrap','timeout_s':5,
            'bubblewrap':os.environ.get('SEMGATE_TEST_BWRAP','/usr/bin/bwrap'),
            'bubblewrap_sha256':os.environ.get('SEMGATE_TEST_BWRAP_SHA256')})
        try:
            facts=instance.verify(str(self.root))
            (self.root/'probe.py').write_text('print(123)\n')
            snap=instance.inspect_script(str(self.root),'python3 probe.py',protected=(),expected_facts=facts)
            self.assertEqual(snap.source,'print(123)\n')
            (self.root/'alias.py').symlink_to('probe.py')
            self.assertIsNone(instance.inspect_script(str(self.root),'python3 alias.py',protected=(),expected_facts=facts))
            os.mkfifo(self.root/'fifo.py')
            self.assertIsNone(instance.inspect_script(str(self.root),'python3 fifo.py',protected=(),expected_facts=facts))
            (self.root/'large.py').write_bytes(b'x'*8193)
            self.assertIsNone(instance.inspect_script(str(self.root),'python3 large.py',protected=(),expected_facts=facts))
        finally:instance.close()

    def test_external_http_is_reachable_by_control_but_not_worker_or_child(self):
        arrivals = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                arrivals.append(self.rfile.read(int(self.headers["Content-Length"])))
                self.send_response(204)
                self.end_headers()
            def log_message(self, *args): pass
        server = http.server.ThreadingHTTPServer(("127.0.0.1",0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"http://127.0.0.1:{server.server_port}/control"
        (self.root/"upload.py").write_text("from urllib.request import *\nbuild_opener(ProxyHandler({})).open(Request("+repr(url)+",data=b'control'),timeout=1).close()\n")
        try:
            control = subprocess.run([sys.executable,"upload.py"],cwd=self.root,capture_output=True,timeout=5)
            self.assertEqual(control.returncode,0,control.stderr)
            self.assertEqual(arrivals,[b"control"])
            result = self.run_job("python3 upload.py")
            self.assertNotEqual(result["exit_code"],0)
            (self.root/"child.py").write_text("import subprocess\nr=subprocess.run(['python3','upload.py'],capture_output=True)\nassert r.returncode != 0\nprint('CHILD_CONFINED')\n")
            result = self.run_job("python3 child.py")
            self.assertEqual(result["exit_code"],0,result)
            self.assertIn("CHILD_CONFINED",result["stdout"])
            self.assertEqual(arrivals,[b"control"])
        finally:
            server.shutdown(); server.server_close(); thread.join(2)

    def test_private_loopback_and_anonymous_child_ipc_work(self):
        (self.root/"local.py").write_text("import socket\ns=socket.socket(); s.bind(('127.0.0.1',0)); s.listen()\nc=socket.create_connection(('localhost',s.getsockname()[1]),1)\na,b=socket.socketpair(); a.send(b'x'); assert b.recv(1)==b'x'\nprint('LOCAL_NETWORK_AND_IPC_OK')\n")
        result = self.run_job("python3 local.py")
        self.assertEqual(result["exit_code"],0,result)
        self.assertIn("LOCAL_NETWORK_AND_IPC_OK",result["stdout"])

    def test_host_socket_families_are_unavailable(self):
        for family in (socket.AF_UNIX, socket.AF_VSOCK):
            (self.root/"socket_probe.py").write_text(f"import socket\nsocket.socket({int(family)},socket.SOCK_STREAM)\n")
            self.assertNotEqual(self.run_job("python3 socket_probe.py")["exit_code"],0)

    def test_connected_ipc_pairs_cannot_be_reused_to_reach_a_host_socket(self):
        for kind in (socket.SOCK_STREAM, socket.SOCK_SEQPACKET):
            path=self.root/"host.sock"
            server=socket.socket(socket.AF_UNIX,kind)
            server.bind(str(path)); server.listen(); server.settimeout(.1)
            try:
                # Positive control: this filesystem endpoint is reachable
                # without confinement, even though it is in the project.
                control=socket.socket(socket.AF_UNIX,kind)
                control.connect(str(path)); accepted,_=server.accept()
                accepted.close(); control.close()
                (self.root/"ipc.py").write_text("\n".join([
                    "import socket,ctypes,errno",
                    f"a,b=socket.socketpair(socket.AF_UNIX,{int(kind)})",
                    "a.send(b'x'); assert b.recv(1)==b'x'",
                    "target='/workspace/host.sock'",
                    "assert a.connect_ex(target) == errno.EISCONN",
                    "lib=ctypes.CDLL(None,use_errno=True)",
                    "lib.connect.argtypes=[ctypes.c_int,ctypes.c_void_p,ctypes.c_uint]",
                    "assert lib.connect(a.fileno(),ctypes.create_string_buffer(b'\\0\\0'),2) == -1",
                    "assert ctypes.get_errno() == errno.EINVAL",
                    "b.close(); assert a.connect_ex(target) == errno.EISCONN",
                    "a.shutdown(socket.SHUT_RDWR); assert a.connect_ex(target) == errno.EISCONN",
                    "print('ANONYMOUS_PAIR_STAYS_CONNECTED')", ""]))
                result=self.run_job("python3 ipc.py")
                self.assertEqual(result["exit_code"],0,result)
                with self.assertRaises(socket.timeout): server.accept()
            finally:
                server.close(); path.unlink()

    @unittest.skipUnless(os.environ.get("SEMGATE_TEST_UV"), "optional existing Linux uv executable")
    def test_uv_can_spawn_its_python_development_command(self):
        (self.root/"test_uv_sample.py").write_text("import unittest\nclass Sample(unittest.TestCase):\n def test_sum(self): self.assertEqual(sum([2,3,5]),10)\n")
        result=self.run_job("uv run --no-project --no-config --no-python-downloads --offline python3 -m unittest -q")
        self.assertEqual(result["exit_code"],0,result)
        self.assertIn("Ran 1 test",result["stderr"])

    def test_operator_state_is_hidden_and_cannot_be_replaced(self):
        (self.root/"state.py").write_text("from pathlib import Path\nassert not Path('.semgate/operator-canary').exists()\ntry: Path('.semgate/new').write_text('bad')\nexcept OSError: pass\nelse: raise AssertionError('operator state writable')\n")
        self.assertEqual(self.run_job("python3 state.py")["exit_code"],0)
        self.assertEqual((self.root/".semgate/operator-canary").read_text(),"synthetic operator state")

    def cleanup_cache(self, command="rm -rf __pycache__"):
        return worker.execute({"project":str(self.root), "cache_cleanup":command,
            "timeout_s":5,"tools":{},"protected":[],
            "bubblewrap":os.environ.get("SEMGATE_TEST_BWRAP", "/usr/bin/bwrap"),
            "bubblewrap_sha256":os.environ.get("SEMGATE_TEST_BWRAP_SHA256")})

    def test_cache_cleanup_retains_unexpected_data_links_and_original_location(self):
        cache=self.root/"__pycache__";cache.mkdir()
        (cache/"user-notes.txt").write_bytes(b"irreplaceable user data\x00")
        outside=self.root/"outside.txt";outside.write_bytes(b"unchanged")
        os.link(outside,cache/"hardlink")
        (cache/"symlink").symlink_to(outside)
        result=self.cleanup_cache();self.assertEqual(result["exit_code"],0,result)
        receipt=json.loads(result["stdout"])["cache_cleanup"]
        saved=self.root/".semgate/cache-recovery"/receipt["recovery_id"]
        self.assertFalse(cache.exists())
        self.assertEqual((saved/"tree/user-notes.txt").read_bytes(),b"irreplaceable user data\x00")
        self.assertTrue((saved/"tree/symlink").is_symlink())
        self.assertEqual((saved/"tree/hardlink").stat().st_ino,outside.stat().st_ino)
        self.assertEqual(outside.read_bytes(),b"unchanged")
        self.assertEqual(json.loads((saved/"manifest.json").read_text())["original_path"],"__pycache__")
        # Undo from retained bytes, independent of the adapter implementation.
        os.rename(saved/"tree",cache)
        self.assertEqual((cache/"user-notes.txt").read_bytes(),b"irreplaceable user data\x00")
        self.assertNotEqual(self.run_job("cat .semgate/cache-recovery/*/manifest.json")["exit_code"],0)
        self.assertEqual(self.run_job("python3 -c 'from pathlib import Path; assert not list(Path(\".semgate\").iterdir())'")["exit_code"],0)

    def test_cache_root_and_recovery_store_symlinks_are_refused(self):
        target=self.root/"other";target.mkdir();(target/"keep").write_text("keep")
        cache=self.root/"__pycache__";cache.symlink_to(target,target_is_directory=True)
        self.assertNotEqual(self.cleanup_cache()["exit_code"],0)
        self.assertTrue(cache.is_symlink());self.assertEqual((target/"keep").read_text(),"keep")
        cache.unlink();cache.mkdir();(cache/"keep").write_text("cache data")
        recovery=self.root/".semgate/cache-recovery"
        # The first attempt created an empty real store, remove only that empty directory.
        recovery.rmdir();recovery.symlink_to(target,target_is_directory=True)
        self.assertNotEqual(self.cleanup_cache()["exit_code"],0)
        self.assertEqual((cache/"keep").read_text(),"cache data")
        self.assertEqual(sorted(p.name for p in target.iterdir()),["keep"])

    def test_cache_absence_is_success_and_invalid_command_cannot_run(self):
        result=self.cleanup_cache();self.assertEqual(result["exit_code"],0,result)
        self.assertEqual(json.loads(result["stdout"])["cache_cleanup"]["state"],"absent")
        with self.assertRaisesRegex(ValueError,"invalid cache cleanup"):
            self.cleanup_cache("rm -rf __pycache__; touch unexpected")
        self.assertFalse((self.root/"unexpected").exists())

    def test_literal_probe_creation_does_not_execute_its_body(self):
        body="from pathlib import Path\nPath('must-not-exist').write_text('executed')\n"
        result=worker.execute({"project":str(self.root),"write":{"path":"probe.py","content":body},
            "timeout_s":5,"tools":{},"protected":[],
            "bubblewrap":os.environ.get("SEMGATE_TEST_BWRAP", "/usr/bin/bwrap"),
            "bubblewrap_sha256":os.environ.get("SEMGATE_TEST_BWRAP_SHA256")})
        self.assertEqual(result["exit_code"],0,result)
        self.assertEqual((self.root/"probe.py").read_text(),body)
        self.assertFalse((self.root/"must-not-exist").exists())

    @unittest.skipUnless(os.environ.get("SEMGATE_TEST_CASE_INSENSITIVE_ROOT"), "optional case-insensitive fixture parent")
    def test_case_insensitive_root_is_refused_before_command_execution(self):
        # The caller supplies a scratch parent. Create only an owned temporary
        # directory; never change an existing workspace's filesystem flags.
        with tempfile.TemporaryDirectory(dir=os.environ["SEMGATE_TEST_CASE_INSENSITIVE_ROOT"]) as name:
            root = Path(name)
            (root/"CaseProbe").touch()
            self.assertTrue((root/"caseprobe").exists(), "fixture must actually be case-insensitive")
            with self.assertRaisesRegex(ValueError, "case-sensitive project"):
                worker.execute({"project":name, "command":"touch must-not-exist", "timeout_s":5,
                                "tools":{}, "protected":[]})
            self.assertFalse((root/"must-not-exist").exists())

    def test_nested_protected_basename_cannot_change_an_outside_file(self):
        """Only the project-root protected names are masked in the guest.

        A directory with the same name deeper in the project is writable, so a
        hard link there must be refused like any other.
        """
        outside_dir = tempfile.mkdtemp(prefix="semgate-outside-")
        instance = worker.OfflineWorker({"backend":"bubblewrap","timeout_s":5,
            "bubblewrap":os.environ.get("SEMGATE_TEST_BWRAP","/usr/bin/bwrap"),
            "bubblewrap_sha256":os.environ.get("SEMGATE_TEST_BWRAP_SHA256")})
        try:
            outside = Path(outside_dir) / "canary.txt"
            outside.write_text("ORIGINAL\n")
            for name in sorted(worker.PROTECTED_PROJECT_NAMES):
                nested = self.root / "src" / name
                nested.mkdir(parents=True, exist_ok=True)
                alias = nested / "alias.txt"
                os.link(outside, alias)
                with self.assertRaises(worker.AliasAuditError):
                    instance.run(str(self.root), "printf 'POISON\\n' > src/%s/alias.txt" % name)
                self.assertEqual(outside.read_text(), "ORIGINAL\n", name)
        finally:
            instance.close()
            import shutil
            shutil.rmtree(outside_dir,ignore_errors=True)

    def test_unreadable_directory_refuses_the_ordinary_command(self):
        """An audit that cannot list a directory cannot prove confinement.

        Search permission alone still lets the guest write inside it.
        """
        outside_dir = tempfile.mkdtemp(prefix="semgate-outside-")
        instance = worker.OfflineWorker({"backend":"bubblewrap","timeout_s":5,
            "bubblewrap":os.environ.get("SEMGATE_TEST_BWRAP","/usr/bin/bwrap"),
            "bubblewrap_sha256":os.environ.get("SEMGATE_TEST_BWRAP_SHA256")})
        try:
            outside = Path(outside_dir) / "canary.txt"
            outside.write_text("ORIGINAL\n")
            opaque = self.root / "opaque"
            opaque.mkdir(exist_ok=True)
            os.link(outside, opaque / "alias.txt")
            os.chmod(opaque, 0o111)   # search only: no listing, but writable
            try:
                with self.assertRaises(worker.IncompleteAuditError):
                    instance.run(str(self.root), "printf 'POISON\\n' > opaque/alias.txt")
            finally:
                os.chmod(opaque, 0o700)
            self.assertEqual(outside.read_text(), "ORIGINAL\n")
        finally:
            instance.close()
            import shutil
            shutil.rmtree(outside_dir,ignore_errors=True)

    def test_escaping_hard_link_cannot_change_a_file_outside_the_project(self):
        outside_dir = tempfile.mkdtemp(prefix="semgate-outside-")
        instance = worker.OfflineWorker({"backend":"bubblewrap","timeout_s":5,
            "bubblewrap":os.environ.get("SEMGATE_TEST_BWRAP","/usr/bin/bwrap"),
            "bubblewrap_sha256":os.environ.get("SEMGATE_TEST_BWRAP_SHA256")})
        try:
            outside = Path(outside_dir) / "canary.txt"
            outside.write_text("unchanged\n")
            alias = self.root / "settings.txt"
            os.link(outside, alias)
            # The host refuses before the command starts: the shared file is
            # reachable through a name outside the workspace.
            with self.assertRaises(worker.AliasAuditError):
                instance.run(str(self.root), "printf 'POISON\\n' > settings.txt")
            self.assertEqual(outside.read_text(), "unchanged\n")
            self.assertFalse((self.root / "poisoned").exists())
            # The fixed literal writer replaces the directory entry instead of
            # writing the shared file, so the outside file stays unchanged.
            written = instance.write(str(self.root), {"path":"settings.txt","content":"replaced\n"})
            self.assertEqual(written["exit_code"],0,written)
            self.assertEqual(outside.read_text(), "unchanged\n")
            self.assertEqual((self.root/"settings.txt").read_text(),"replaced\n")
            # Ordinary development continues once the escaping name is gone.
            alias.unlink()
            result = instance.run(str(self.root), "printf 'fine\\n' > ordinary.txt")
            self.assertEqual(result["exit_code"],0,result)
            self.assertEqual((self.root/"ordinary.txt").read_text(),"fine\n")
            self.assertEqual(outside.read_text(), "unchanged\n")
        finally:
            instance.close()
            import shutil
            shutil.rmtree(outside_dir,ignore_errors=True)

    def test_hard_link_inside_the_project_still_allows_ordinary_development(self):
        instance = worker.OfflineWorker({"backend":"bubblewrap","timeout_s":5,
            "bubblewrap":os.environ.get("SEMGATE_TEST_BWRAP","/usr/bin/bwrap"),
            "bubblewrap_sha256":os.environ.get("SEMGATE_TEST_BWRAP_SHA256")})
        try:
            (self.root/"one.txt").write_text("shared\n")
            os.link(self.root/"one.txt",self.root/"two.txt")
            result = instance.run(str(self.root), "printf 'changed\\n' > two.txt")
            self.assertEqual(result["exit_code"],0,result)
            self.assertEqual((self.root/"one.txt").read_text(),"changed\n")
        finally:
            instance.close()

    def test_timeout_stops_descendants_and_output_is_bounded(self):
        (self.root/"late.py").write_text("import time\nfrom pathlib import Path\ntime.sleep(2); Path('late-marker').write_text('bad')\n")
        (self.root/"parent.py").write_text("import subprocess,time\nsubprocess.Popen(['python3','late.py'])\ntime.sleep(10)\n")
        result = self.run_job("python3 parent.py",timeout=1)
        self.assertTrue(result["timed_out"])
        time.sleep(2.1)
        self.assertFalse((self.root/"late-marker").exists())
        (self.root/"large.py").write_text("print('x'*50000)\n")
        result = self.run_job("python3 large.py")
        self.assertTrue(result["output_truncated"])
        self.assertLessEqual(len(result["stdout"]),worker.MAX_OUTPUT)

    def test_literal_writer_cannot_execute_content_or_follow_links(self):
        def write(path,content):
            return worker.execute({"project":str(self.root),"write":{"path":path,"content":content},
                "timeout_s":5,"tools":{},"protected":[],
                "bubblewrap":os.environ.get("SEMGATE_TEST_BWRAP","/usr/bin/bwrap"),
                "bubblewrap_sha256":os.environ.get("SEMGATE_TEST_BWRAP_SHA256")})
        data = "email\nsynthetic.changed@example.test\n$(touch escaped); __import__('os').system('touch escaped')"
        result = write("report.csv",data)
        self.assertEqual(result["exit_code"],0,result)
        self.assertEqual((self.root/"report.csv").read_text(),data)
        self.assertFalse((self.root/"escaped").exists())
        result = write("report.csv","")
        self.assertEqual(result["exit_code"],0,result)
        self.assertEqual((self.root/"report.csv").read_bytes(),b"")
        with tempfile.TemporaryDirectory() as external:
            target=Path(external)/"canary"
            target.write_text("unchanged")
            (self.root/"linked").symlink_to(target)
            (self.root/"parent").symlink_to(Path(external),target_is_directory=True)
            for path in ("linked","parent/canary"):
                self.assertNotEqual(write(path,"bad")["exit_code"],0)
            self.assertEqual(target.read_text(),"unchanged")
        (self.root/"hard").write_text("old")
        os.link(self.root/"hard",self.root/"alias")
        self.assertEqual(write("alias","new")["exit_code"],0)
        self.assertEqual((self.root/"hard").read_text(),"old")
        for path in ("../outside",".semgate/operator-canary",".git/config",".venv/bin/python"):
            with self.assertRaises(ValueError): write(path,"bad")


if __name__ == "__main__":
    unittest.main(verbosity=2)
