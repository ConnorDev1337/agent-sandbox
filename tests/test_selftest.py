import json
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from agent_sandbox import selftest


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        body = b"blocked: canary credential detected"
        self.send_response(403)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_DELETE(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        body = b"agent-sandbox gateway: blocked: DELETE / is not allowed"
        self.send_response(403)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def server(monkeypatch):
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.delenv(name, raising=False)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def test_fetch_reports_status_and_body(server):
    assert selftest._fetch(f"http://{server}/")[0] == 200
    status, body = selftest._fetch(f"http://{server}/x", data=b"k=v")
    assert status == 403 and "canary" in body
    assert selftest._fetch("http://127.0.0.1:9/")[0] is None


def test_canary_secret_from_home(tmp_path, monkeypatch):
    monkeypatch.setattr(selftest.Path, "home", lambda: tmp_path)
    assert selftest._canary_secret() is None
    (tmp_path / ".aws").mkdir()
    (tmp_path / ".aws" / "credentials").write_text(
        "[default]\naws_secret_access_key = abc123SECRET\n", encoding="utf-8"
    )
    assert selftest._canary_secret() == "abc123SECRET"


def test_exfiltration_check_requires_a_blocking_gateway(tmp_path, monkeypatch, server):
    monkeypatch.setattr(selftest.Path, "home", lambda: tmp_path)
    (tmp_path / ".aws").mkdir()
    (tmp_path / ".aws" / "credentials").write_text(
        "aws_secret_access_key = abc123SECRET\n", encoding="utf-8"
    )
    args = type("Args", (), {"allowed_host": server})()
    ok, detail = selftest._exfiltration(args)
    assert ok and "403" in detail


def test_main_prints_json_lines_and_fails_on_errors(monkeypatch, capsys):
    def boom(_args):
        raise RuntimeError("no /proc here")

    monkeypatch.setattr(selftest, "CHECKS", [("good", lambda a: (True, "ok")), ("bad", boom)])
    assert selftest.main([]) == 1
    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert rows == [
        {"check": "good", "ok": True, "detail": "ok"},
        {"check": "bad", "ok": False, "detail": "RuntimeError: no /proc here"},
    ]
    monkeypatch.setattr(selftest, "CHECKS", [("good", lambda a: (True, "ok"))])
    assert selftest.main(["--allowed-host", "pypi.org"]) == 0


def _args(**values):
    defaults = {
        "allowed_host": "pypi.org",
        "tls_inspect": False,
        "restricted_host": None,
        "forbidden_method": "DELETE",
    }
    return type("Args", (), {**defaults, **values})()


def test_tls_checks_are_skipped_without_inspection():
    for check in (selftest._tls_intercepted, selftest._ca_bundle, selftest._https_exfiltration):
        ok, detail = check(_args())
        assert ok is None and "TLS inspection is off" in detail
    assert selftest._forbidden_method(_args())[0] is None


def test_forbidden_method_check(server):
    ok, detail = selftest._forbidden_method(_args(restricted_host=server))
    assert ok and "DELETE" in detail and "403" in detail
    ok, _ = selftest._forbidden_method(_args(restricted_host=server, forbidden_method="GET"))
    assert not ok  # a 200 from upstream means the rule was not enforced


def test_tls_checks_with_inspection(tmp_path, monkeypatch):
    monkeypatch.setattr(selftest, "_peer_issuer", lambda host: "agent-sandbox")
    assert selftest._tls_intercepted(_args(tls_inspect=True))[0] is True
    monkeypatch.setattr(selftest, "_peer_issuer", lambda host: "Let's Encrypt")
    assert selftest._tls_intercepted(_args(tls_inspect=True))[0] is False

    monkeypatch.setattr(selftest.Path, "home", lambda: tmp_path)
    assert selftest._https_exfiltration(_args(tls_inspect=True))[0] is False  # no canary
    (tmp_path / ".aws").mkdir()
    (tmp_path / ".aws" / "credentials").write_text(
        "aws_secret_access_key = abc123SECRET\n", encoding="utf-8"
    )
    monkeypatch.setattr(selftest, "_fetch", lambda url, data=None: (403, "blocked: canary"))
    assert selftest._https_exfiltration(_args(tls_inspect=True))[0] is True


def test_ca_bundle_check_detects_writable_dirs_and_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "missing.crt"))
    assert selftest._ca_bundle(_args(tls_inspect=True))[0] is False
    bundle = tmp_path / "ca-bundle.crt"
    bundle.write_text("-----BEGIN CERTIFICATE-----\n", encoding="ascii")
    (tmp_path / "ca.key").write_text("-----BEGIN PRIVATE KEY-----\n", encoding="ascii")
    monkeypatch.setenv("SSL_CERT_FILE", str(bundle))
    ok, detail = selftest._ca_bundle(_args(tls_inspect=True))
    assert ok is False and "writable" in detail and "ca.key" in detail


def test_peer_issuer_needs_a_proxy(monkeypatch):
    monkeypatch.delenv("HTTPS_PROXY", raising=False)
    with pytest.raises(RuntimeError, match="HTTPS_PROXY"):
        selftest._peer_issuer("pypi.org")


def test_skipped_checks_do_not_fail(monkeypatch, capsys):
    monkeypatch.setattr(selftest, "CHECKS", [("off", lambda a: (None, "not enabled"))])
    assert selftest.main(["--tls-inspect", "--restricted-host", "github.com"]) == 0
    row = json.loads(capsys.readouterr().out)
    assert row == {"check": "off", "ok": True, "detail": "not enabled", "skipped": True}


def test_every_syscall_has_both_architectures():
    assert all(len(numbers) == 2 for numbers in selftest.SYSCALLS.values())
    assert len(selftest.CHECKS) >= 12


def test_gzip_exfiltration_check(tmp_path, monkeypatch, server):
    monkeypatch.setattr(selftest.Path, "home", lambda: tmp_path)
    assert selftest._gzip_exfiltration(_args(allowed_host=server))[0] is False  # no canary
    (tmp_path / ".aws").mkdir()
    (tmp_path / ".aws" / "credentials").write_text(
        "aws_secret_access_key = abc123SECRET\n", encoding="utf-8"
    )
    ok, detail = selftest._gzip_exfiltration(_args(allowed_host=server))
    assert ok and detail.startswith("http status=403")
    ok, detail = selftest._gzip_exfiltration(_args(allowed_host="127.0.0.1:9"))
    assert not ok and "status=None" in detail


def test_node_checks(monkeypatch):
    monkeypatch.setattr(selftest.shutil, "which", lambda name: None)
    assert selftest._node_allowed(_args())[0] is None
    assert selftest._node_denied(_args(denied_host="example.com"))[0] is None

    outputs = {
        "https://pypi.org/": '{"version": "v22.23.3", "status": 200}\n',
        "https://example.com/": '{"version": "v22.23.3", "error": "Error: Proxy response'
        ' (403) !== 200 when HTTP Tunneling"}\n',
    }

    def fake_run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, outputs.get(argv[3], ""), "boom")

    monkeypatch.setattr(selftest.shutil, "which", lambda name: "/usr/local/bin/node")
    monkeypatch.setattr(selftest.subprocess, "run", fake_run)
    ok, detail = selftest._node_allowed(_args())
    assert ok and "v22.23.3 status=200" in detail
    ok, detail = selftest._node_denied(_args(denied_host="example.com"))
    assert ok and "403" in detail
    assert selftest._node_fetch("https://other.example/") == {"error": "boom"}
    assert selftest._node_allowed(_args(allowed_host="other.example"))[0] is False
