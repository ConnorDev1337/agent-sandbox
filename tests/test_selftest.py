import json
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


def test_every_syscall_has_both_architectures():
    assert all(len(numbers) == 2 for numbers in selftest.SYSCALLS.values())
    assert len(selftest.CHECKS) >= 12
