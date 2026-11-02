"""Site de démonstration LOCAL : connexion par formulaire (jeton CSRF), articles protégés,
robots.txt, limitation 429. Sert aux tests et à la démo, sans cible réelle.
Lancer :  python -m tools.demo_site      (http://127.0.0.1:8080, identifiants analyste / demo123)"""
import secrets
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

ARTICLES = {
    "1": ("Campagne Foo", """<p>L'équipe a observé payload.dll sur le poste interne 10.0.0.5 ; voir aussi
partner.example. Version du composant : 1.2.3.4.</p><h2>IOC</h2><pre class="iocs">
hxxp://evil-c2[.]example/gate.php
203.0.113.77
bad-domain[.]example
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</pre>"""),
    "2": ("Rapport Bar", """<p>Résumé.</p><pre class="iocs">198.51.100.23
d41d8cd98f00b204e9800998ecf8427e</pre>"""),
    "3": ("Alerte Baz", """<p>Texte.</p><pre class="iocs">192.0.2.99
second-domain[.]example</pre>"""),
    "4": ("Note sans IOC", "<p>Aucun indicateur ici.</p>"),
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code=200, body="", headers=None):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        data = body.encode()
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _cookie(self, name):
        c = SimpleCookie(self.headers.get("Cookie", ""))
        return c[name].value if name in c else None

    def _authed(self):
        return self._cookie("session") in self.server.sessions

    def do_GET(self):
        u = urlparse(self.path)
        self.server.hits.append(u.path)
        if u.path == "/robots.txt":
            return self._send(200, "User-agent: *\nDisallow: /private\n")
        if u.path == "/login":
            tok = secrets.token_hex(8)
            return self._send(200, f"""<form method="post" action="/login">
<input type="hidden" name="csrf_token" value="{tok}"><input name="username">
<input type="password" name="password"></form>""", {"Set-Cookie": f"pre={tok}; Path=/"})
        if not self._authed():
            return self._send(302, "", {"Location": "/login"})
        if u.path == "/":
            page = parse_qs(u.query).get("page", ["1"])[0]
            if page == "1":
                ids = [k for k in self.server.articles if k in ("1", "2", "3")]
                links = "".join(f'<a class="title" href="/a/{i}">A{i}</a>' for i in ids)
                links += '<a class="title" href="/private/x">interdit</a>'
                links += '<a class="title" href="https://other.example/a">externe</a>'
                nxt = '<a class="next" href="/?page=2">suivant</a>'
            else:
                links = "".join(f'<a class="title" href="/a/{i}">A{i}</a>'
                                for i in self.server.articles if i not in ("1", "2", "3"))
                nxt = ""
            return self._send(200, f'<a class="logout" href="/logout">quitter</a>{links}{nxt}')
        if u.path.startswith("/a/"):
            aid = u.path.split("/")[-1]
            if aid == "3" and not self.server.state.get("a3_throttled"):
                self.server.state["a3_throttled"] = True
                return self._send(429, "trop de requêtes", {"Retry-After": "0"})
            title, body = self.server.articles[aid]
            return self._send(200, f'<a class="logout" href="/l">q</a><h1>{title}</h1>'
                                   f'<div class="article-body">{body}</div>')
        self._send(404, "introuvable")

    def do_POST(self):
        self.server.hits.append("POST " + self.path)
        form = parse_qs(self.rfile.read(int(self.headers.get("Content-Length", 0))).decode())
        g = lambda k: form.get(k, [""])[0]
        if (g("csrf_token") and g("csrf_token") == self._cookie("pre")
                and g("username") == self.server.user and g("password") == self.server.password):
            sid = secrets.token_hex(16)
            self.server.sessions.add(sid)
            self.server.logins += 1
            return self._send(302, "", {"Location": "/", "Set-Cookie": f"session={sid}; Path=/"})
        self.server.failed_logins += 1
        self._send(200, '<form method="post"><input type="password" name="password"></form>Refusé')


def make_server(port=0, user="analyste", password="demo123"):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    srv.user, srv.password = user, password
    srv.sessions, srv.hits, srv.state = set(), [], {}
    srv.logins = srv.failed_logins = 0
    srv.articles = dict(ARTICLES)
    return srv


if __name__ == "__main__":
    s = make_server(8080)
    print("Site de démonstration : http://127.0.0.1:8080  (analyste / demo123)  Ctrl+C pour arrêter")
    s.serve_forever()
