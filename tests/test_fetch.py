import socket
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from jorisjonkers_commons.identity import IdentityUnavailable, Request, Response, urllib_fetch


class Identity(BaseHTTPRequestHandler):
    """Answers a POST with its body and 200, and anything else with 404."""

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(self.headers["Authorization"].encode() + b" " + body)

    def do_GET(self) -> None:
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"no such keys")

    def log_message(self, format: str, *args: object) -> None:
        return None


@pytest.fixture
def identity() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Identity)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def test_urllib_fetch_sends_the_request_and_returns_identitys_answer(identity: str) -> None:
    request = Request("POST", f"{identity}/oidc/introspect", {"Authorization": "Basic d2ViOnM="}, b"token=t")

    assert urllib_fetch(request) == Response(200, b"Basic d2ViOnM= token=t")


def test_urllib_fetch_returns_an_error_status_as_an_answer(identity: str) -> None:
    assert urllib_fetch(Request("GET", f"{identity}/oidc/keys")) == Response(404, b"no such keys")


def test_urllib_fetch_raises_identity_unavailable_when_nothing_answers() -> None:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        closed = s.getsockname()[1]

    with pytest.raises(IdentityUnavailable):
        urllib_fetch(Request("GET", f"http://127.0.0.1:{closed}/oidc/keys"))
