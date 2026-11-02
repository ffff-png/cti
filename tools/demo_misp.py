"""Faux serveur MISP LOCAL (API /attributes/restSearch) pour les tests et la démo.
Lancer :  python -m tools.demo_misp      (http://127.0.0.1:8081, clé : cle-demo-misp)"""
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        self.server.requests.append({"path": self.path, "body": body, "auth": self.headers.get("Authorization")})
        if self.headers.get("Authorization") != self.server.key:
            return self._json(403, {"name": "Authentication failed. Please make sure you pass the API key."})
        if self.path != "/attributes/restSearch":
            return self._json(404, {"name": "not found"})
        wanted = body.get("type", {}).get("OR") if isinstance(body.get("type"), dict) else body.get("type")
        rows = [a for a in self.server.attributes
                if (not wanted or a["type"] in wanted)
                and (not body.get("to_ids") or a["to_ids"])
                and int(a["timestamp"]) > int(body.get("timestamp", 0))]
        limit, page = int(body.get("limit", 100)), int(body.get("page", 1))
        self._json(200, {"response": {"Attribute": rows[(page - 1) * limit: page * limit]}})


def make_server(port=0, key="cle-demo-misp"):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    srv.key, srv.requests = key, []
    now = int(time.time())
    def attr(i, typ, value, to_ids=True, age=3600):
        return {"id": str(i), "event_id": "1", "event_uuid": "uuid-1", "type": typ, "category": "Network activity",
                "value": value, "to_ids": to_ids, "timestamp": str(now - age + i), "comment": f"démo {i}"}
    srv.attributes = [
        attr(1, "ip-dst", "203.0.113.5"),
        attr(2, "ip-src|port", "198.51.100.7|8080"),
        attr(3, "domain|ip", "evil.example|192.0.2.10"),
        attr(4, "url", "http://bad.example/x.php"),
        attr(5, "sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        attr(6, "filename|md5", "doc.exe|d41d8cd98f00b204e9800998ecf8427e"),
        attr(7, "ip-dst", "999.1.1.1"),                    # valeur invalide
        attr(8, "ip-dst", "203.0.113.200", to_ids=False),  # non IDS : exclu par défaut
    ]
    srv.now = now
    return srv


if __name__ == "__main__":
    s = make_server(8081)
    print("Faux MISP : http://127.0.0.1:8081  (clé : cle-demo-misp)  Ctrl+C pour arrêter")
    s.serve_forever()
