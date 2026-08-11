#!/usr/bin/env python3
"""GCP / Firebase unauthenticated-exposure recon.

Stdlib only (urllib/concurrent/smtplib) so it runs anywhere cron does.
Every check appends structured Findings; output goes to stdout (colored),
--json, and/or --html, and can be emailed straight from cron.
"""

import argparse
import concurrent.futures as cf
import html
import json
import os
import smtplib
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from email.message import EmailMessage

# --- severities ---------------------------------------------------------------
VULN, OK, INFO, WARN, UNKNOWN = "vuln", "ok", "info", "warn", "unknown"
PREFIX = {VULN: "[X]", OK: "[OK]", INFO: "[+]", WARN: "[!]", UNKNOWN: "[?]"}
COLOR = {VULN: "31", OK: "32", INFO: "36", WARN: "33", UNKNOWN: "35"}

REGIONS = [
    "us-central1", "us-east1", "us-east4", "us-west1",
    "northamerica-northeast1", "southamerica-east1",
    "europe-west1", "europe-west2", "europe-west3",
]
COMMON_FUNCTIONS = [
    "api", "app", "auth", "login", "register", "signup", "webhook",
    "upload", "download", "contracts", "contratos", "clientes", "users",
    "admin", "sendEmail", "notification", "notifications", "payment", "payments",
]
COMMON_PATHS = [
    "/", "/api", "/api/v1", "/admin", "/login", "/debug", "/health", "/status",
    "/swagger.json", "/openapi.json", "/api-docs", "/docs",
    "/.env", "/config.js", "/firebase-config.js", "/main.js",
]
DOC_PATHS = ["/swagger.json", "/openapi.json", "/api-docs", "/docs",
             "/v1/swagger.json", "/v1/openapi.json"]
SENSITIVE_RE = ("apikey", "projectid", "storagebucket", "databaseurl",
                "authdomain", "messagingsenderid", "appid", "private_key",
                "client_email")

MODULES = ["hosting", "hosting-paths", "identity-toolkit", "remote-config",
           "firestore", "storage", "rtdb", "cloud-run", "cloud-functions",
           "api-docs"]


@dataclass
class Finding:
    module: str
    action: str
    target: str
    status: object          # int http code, or None on connection error
    severity: str
    message: str
    url: str = ""
    detail: str = ""


@dataclass
class Scanner:
    project_id: str
    bucket: str
    api_key: str = ""
    app_id: str = ""
    wordlist: str = ""
    timeout: int = 10
    jobs: int = 5
    color: bool = True
    findings: list = field(default_factory=list)

    # --- io -------------------------------------------------------------------
    def record(self, module, action, target, status, severity, message,
               url="", detail=""):
        f = Finding(module, action, target, status, severity, message, url, detail)
        self.findings.append(f)
        line = f"{PREFIX[severity]} {message}"
        if self.color:
            line = f"\033[{COLOR[severity]}m{line}\033[0m"
        print(line)
        return f

    def log(self, msg):
        print(f"\033[36m[*]\033[0m {msg}" if self.color else f"[*] {msg}")

    def banner(self, msg):
        bar = "=" * 43
        if self.color:
            bar = f"\033[34m{bar}\033[0m"
        print(f"\n{bar}\n{'[!] ' + msg}\n{bar}")

    # --- http -----------------------------------------------------------------
    def http(self, method, url, data=None, ctype=None):
        headers = {}
        body = None
        if data is not None:
            if isinstance(data, (dict, list)):
                body = json.dumps(data).encode()
                headers["Content-Type"] = "application/json"
            else:
                body = data.encode() if isinstance(data, str) else data
                if ctype:
                    headers["Content-Type"] = ctype
        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")
        except Exception:                     # URLError, timeout, ssl, dns...
            return None, ""

    # --- checks ---------------------------------------------------------------
    def check_hosting(self):
        self.banner("Firebase Hosting init.js")
        url = f"https://{self.project_id}.web.app/__/firebase/init.js"
        self.log(f"URL: {url}")
        st, body = self.http("GET", url)
        if st == 200:
            if any(k in body.lower() for k in
                   ("apikey", "projectid", "storagebucket", "databaseurl",
                    "authdomain", "messagingsenderid", "appid")):
                self.record("hosting", "GET", url, st, VULN,
                            f"Firebase client config exposed: {url}", url, body)
            else:
                self.record("hosting", "GET", url, st, INFO,
                            f"init.js is public: {url}", url)
        elif st == 404:
            self.record("hosting", "GET", url, st, OK, "init.js not found", url)
        elif st in (401, 403):
            self.record("hosting", "GET", url, st, OK, "init.js blocked", url)
        else:
            self.record("hosting", "GET", url, st, UNKNOWN,
                        f"init.js HTTP {st}", url)

    def check_hosting_paths(self):
        self.banner("Firebase Hosting common paths")
        hosts = [f"https://{self.project_id}.web.app",
                 f"https://{self.project_id}.firebaseapp.com"]
        interesting = {"/.env", "/config.js", "/firebase-config.js",
                       "/swagger.json", "/openapi.json", "/api-docs", "/docs"}

        def probe(host, path):
            url = host + path
            st, body = self.http("GET", url)
            if st == 200:
                sev = VULN if path in interesting else INFO
                self.record("hosting-paths", "GET", url, st, sev,
                            f"Public path: {url}", url)
                if any(k in body.lower() for k in SENSITIVE_RE):
                    self.record("hosting-paths", "GET", url, st, VULN,
                                f"Sensitive config at: {url}", url, body[:2000])

        self._fanout([(h, p) for h in hosts for p in COMMON_PATHS], probe)

    def check_api_docs(self):
        self.banner("API Gateway / OpenAPI discovery")
        hosts = [f"https://{self.project_id}.web.app",
                 f"https://{self.project_id}.firebaseapp.com"]

        def probe(host, path):
            url = host + path
            st, body = self.http("GET", url)
            if st == 200:
                self.record("api-docs", "GET", url, st, VULN,
                            f"Public API doc candidate: {url}", url)
                try:
                    j = json.loads(body)
                    if isinstance(j, dict) and (j.get("openapi") or j.get("swagger")
                                                or j.get("paths")):
                        self.record("api-docs", "GET", url, st, VULN,
                                    f"Valid OpenAPI/Swagger doc: {url}", url,
                                    body[:2000])
                except Exception:
                    pass

        self._fanout([(h, p) for h in hosts for p in DOC_PATHS], probe)

    def check_cloud_functions(self):
        self.banner("Cloud Functions")

        def probe(region, fn):
            url = f"https://{region}-{self.project_id}.cloudfunctions.net/{fn}"
            st, body = self.http("GET", url)
            if st in (200, 201, 204, 301, 302, 400, 401, 403, 405):
                self.record("cloud-functions", "GET", url, st, INFO,
                            f"Function candidate: HTTP {st} {url}", url)
                if any(k in body.lower() for k in
                       ("swagger", "openapi", "firebase", "stack", "trace",
                        "error", "exception")):
                    self.record("cloud-functions", "GET", url, st, WARN,
                                f"Interesting response body at: {url}", url,
                                body[:1000])

        self._fanout([(r, fn) for r in REGIONS for fn in COMMON_FUNCTIONS], probe)

    def check_cloud_run(self):
        self.banner("Cloud Run known/guessable hosts")
        self.log("Cloud Run hostnames usually require service-hash discovery.")
        for url in (f"https://api-{self.project_id}.a.run.app",
                    f"https://app-{self.project_id}.a.run.app",
                    f"https://{self.project_id}.a.run.app"):
            st, _ = self.http("GET", url)
            if st in (200, 301, 302, 400, 401, 403, 404, 405):
                self.record("cloud-run", "GET", url, st, INFO,
                            f"Cloud Run candidate: HTTP {st} {url}", url)

    def check_rtdb(self):
        self.banner("Firebase Realtime Database")
        hosts = [f"https://{self.project_id}.firebaseio.com",
                 f"https://{self.project_id}-default-rtdb.firebaseio.com"]
        doc_id = f"audit_{int(time.time())}_{os.getpid()}"
        for host in hosts:
            self.log(host)
            # READ
            st, body = self.http("GET", host + "/.json")
            if st == 200:
                try:
                    j = json.loads(body)
                except Exception:
                    j = None
                if isinstance(j, dict) and j.get("error") == "Permission denied":
                    self.record("rtdb", "READ", host, st, OK, "RTDB read blocked", host)
                elif j not in (None, {}):
                    self.record("rtdb", "READ", host, st, VULN,
                                "POSSIBLE EXPOSURE: RTDB returned public data", host,
                                body[:2000])
                else:
                    self.record("rtdb", "READ", host, st, UNKNOWN,
                                "RTDB returned empty/null", host)
            else:
                self.record("rtdb", "READ", host, st, UNKNOWN, f"RTDB HTTP {st}", host)
            # WRITE / UPDATE / DELETE (was never tested in the shell version)
            path = f"{host}/security_audit_tmp/{doc_id}.json"
            st, _ = self.http("PUT", path, {"security_test": True})
            self.record("rtdb", "WRITE", host, st,
                        VULN if st == 200 else OK if st in (401, 403) else UNKNOWN,
                        f"RTDB unauthenticated WRITE HTTP {st}", path)
            st, _ = self.http("PATCH", path, {"updated": True})
            self.record("rtdb", "UPDATE", host, st,
                        VULN if st == 200 else OK if st in (401, 403) else UNKNOWN,
                        f"RTDB unauthenticated UPDATE HTTP {st}", path)
            st, _ = self.http("DELETE", path)
            self.record("rtdb", "DELETE", host, st,
                        VULN if st == 200 else OK if st in (401, 403) else UNKNOWN,
                        f"RTDB unauthenticated DELETE HTTP {st}", path)

    def check_storage(self):
        self.banner("Cloud Storage / Firebase Storage")
        buckets = list(dict.fromkeys([
            self.bucket,
            f"{self.project_id}.appspot.com",
            f"{self.project_id}.firebasestorage.app",
        ]))
        for bucket in buckets:
            self.log(f"Bucket: {bucket}")
            obj = f"security_audit_tmp_{int(time.time())}_{os.getpid()}.txt"
            enc = urllib.parse.quote(obj, safe="")
            apis = {
                "FB": f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o",
                "GCS": f"https://storage.googleapis.com/storage/v1/b/{bucket}/o",
            }
            uploads = {
                "FB": f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o",
                "GCS": f"https://storage.googleapis.com/upload/storage/v1/b/{bucket}/o",
            }
            for tag, base in apis.items():
                up = uploads[tag]
                for action, (method, url, data) in {
                    f"LIST_{tag}": ("GET", f"{base}?maxResults=5", None),
                    f"WRITE_{tag}": ("POST", f"{up}?uploadType=media&name={enc}",
                                     "storage_rest_audit"),
                    f"GET_{tag}": ("GET", f"{base}/{enc}?alt=media", None),
                    f"DEL_{tag}": ("DELETE", f"{base}/{enc}", None),
                }.items():
                    st, _ = self.http(method, url,
                                      data, "text/plain" if data else None)
                    write = action.startswith(("WRITE", "DEL"))
                    if st == 200:
                        sev = VULN if write or action.startswith("LIST") else INFO
                    elif st in (401, 403):
                        sev = OK
                    else:
                        sev = UNKNOWN
                    self.record("storage", action, bucket, st, sev,
                                f"{action} {bucket} HTTP {st}", url)

    def _firestore_crud(self, base, collection):
        doc_id = f"audit_{int(time.time())}_{os.getpid()}"
        doc = f"{base}/{collection}/{doc_id}"
        payload = {"fields": {"security_test": {"booleanValue": True},
                              "operation": {"stringValue": "unauth_test"}}}
        ops = [
            ("CREATE", "POST", f"{base}/{collection}?documentId={doc_id}", payload),
            ("READ", "GET", doc, None),
            ("UPDATE", "PATCH",
             f"{doc}?updateMask.fieldPaths=operation", payload),
            ("DELETE", "DELETE", doc, None),
        ]
        for action, method, url, data in ops:
            st, _ = self.http(method, url, data)
            sev = VULN if st == 200 else OK if st == 403 else UNKNOWN
            self.record("firestore", action, collection, st, sev,
                        f"{action} {collection} HTTP {st}", url)

    def check_firestore(self):
        self.banner("Firestore REST API")
        base = (f"https://firestore.googleapis.com/v1/projects/"
                f"{self.project_id}/databases/(default)/documents")
        self.log(base)
        st, body = self.http("GET", base)
        if st == 200 and _json_non_empty(body):
            self.record("firestore", "ROOT", "(root)", st, VULN,
                        "POSSIBLE EXPOSURE: Firestore root returned public data",
                        base, body[:2000])
        elif st == 403:
            self.record("firestore", "ROOT", "(root)", st, OK,
                        "Firestore root blocked", base)
        else:
            self.record("firestore", "ROOT", "(root)", st, UNKNOWN,
                        f"Firestore root HTTP {st}", base)

        if self.wordlist:
            cols = _read_wordlist(self.wordlist)
            if not cols:
                self.record("firestore", "WORDLIST", self.wordlist, None, WARN,
                            "Wordlist empty after filtering", self.wordlist)
            else:
                self.log(f"Bruteforcing {len(cols)} collections...")

                def probe(c):
                    st, _ = self.http("GET", f"{base}/{c}?pageSize=1")
                    sev = VULN if st == 200 else OK if st == 403 else UNKNOWN
                    self.record("firestore", "LIST", c, st, sev,
                                f"LIST {c} HTTP {st}", f"{base}/{c}")
                    self._firestore_crud(base, c)

                self._fanout([(c,) for c in cols], probe)
        else:
            self.log("Skipping collection bruteforce (no --wordlist)")

        self.log("Testing unauthenticated CRUD on temp collection...")
        self._firestore_crud(base, "security_audit_tmp")

    def check_identity_toolkit(self):
        self.banner("Firebase Auth / Identity Toolkit")
        if not self.api_key:
            self.record("identity-toolkit", "SKIP", "-", None, WARN,
                        "FIREBASE_API_KEY not set; skipping active Auth checks")
            return
        k = self.api_key
        it = "https://identitytoolkit.googleapis.com"

        # admin config
        url = f"{it}/admin/v2/projects/{self.project_id}/config?key={k}"
        st, body = self.http("GET", url)
        if st == 200 and _json_non_empty(body):
            self.record("identity-toolkit", "GET", "admin-config", st, VULN,
                        "ADMIN CONFIG accessible with API key only", url, body[:2000])
        elif st in (401, 403):
            self.record("identity-toolkit", "GET", "admin-config", st, OK,
                        "Admin config blocked", url)
        else:
            self.record("identity-toolkit", "GET", "admin-config", st, UNKNOWN,
                        f"Admin config HTTP {st}", url)

        # recaptcha (normally public)
        url = (f"{it}/v2/recaptchaConfig?key={k}&clientType=CLIENT_TYPE_WEB"
               f"&version=RECAPTCHA_ENTERPRISE")
        st, _ = self.http("GET", url)
        sev = INFO if st == 200 else OK if st in (401, 403) else UNKNOWN
        self.record("identity-toolkit", "GET", "recaptcha-config", st, sev,
                    f"reCAPTCHA config HTTP {st}", url)

        protected = {
            "account-list":
                f"{it}/v1/projects/{self.project_id}/accounts:batchGet?maxResults=1&key={k}",
            "oidc-idp":
                f"{it}/v2/projects/{self.project_id}/oauthIdpConfigs?key={k}",
            "saml-idp":
                f"{it}/v2/projects/{self.project_id}/inboundSamlConfigs?key={k}",
            "default-idp":
                f"{it}/v2/projects/{self.project_id}/defaultSupportedIdpConfigs?key={k}",
            "legacy-config":
                f"https://www.googleapis.com/identitytoolkit/v3/relyingparty/getProjectConfig?key={k}",
        }
        for name, url in protected.items():
            st, body = self.http("GET", url)
            if st == 200:
                self.record("identity-toolkit", "GET", name, st, VULN,
                            f"{name} accessible with API key only", url, body[:2000])
            elif st in (401, 403):
                self.record("identity-toolkit", "GET", name, st, OK,
                            f"{name} blocked", url)
            else:
                self.record("identity-toolkit", "GET", name, st, UNKNOWN,
                            f"{name} HTTP {st}", url)

        # anonymous signup
        url = f"{it}/v1/accounts:signUp?key={k}"
        st, body = self.http("POST", url, {"returnSecureToken": True})
        id_token = ""
        try:
            id_token = json.loads(body).get("idToken", "")
        except Exception:
            pass
        if st == 200 and id_token:
            self.record("identity-toolkit", "POST", "anonymous-signup", st, VULN,
                        "Anonymous signup appears ENABLED", url)
            d = self.http("POST", f"{it}/v1/accounts:delete?key={k}",
                          {"idToken": id_token})[0]
            self.log("Cleaned up audit account" if d == 200
                     else f"Cleanup HTTP {d}")
        elif "ADMIN_ONLY_OPERATION" in body:
            self.record("identity-toolkit", "POST", "anonymous-signup", st, OK,
                        "Anonymous signup blocked/admin-only", url)
        else:
            self.record("identity-toolkit", "POST", "anonymous-signup", st, UNKNOWN,
                        f"Auth signup HTTP {st}", url)

    def check_remote_config(self):
        self.banner("Firebase Remote Config")
        if not self.api_key:
            self.record("remote-config", "SKIP", "-", None, WARN,
                        "FIREBASE_API_KEY not set; skipping")
            return
        if not self.app_id:
            self.record("remote-config", "SKIP", "-", None, WARN,
                        "FIREBASE_APP_ID not set; Remote Config needs appId")
            return
        url = (f"https://firebaseremoteconfig.googleapis.com/v1/projects/"
               f"{self.project_id}/namespaces/firebase:fetch?key={self.api_key}")
        st, body = self.http("POST", url, {"appId": self.app_id,
                                           "appInstanceId": "scanner",
                                           "appInstanceIdToken": "scanner"})
        if st == 200 and _json_non_empty(body):
            self.record("remote-config", "POST", self.app_id, st, INFO,
                        "Remote Config returned data", url, body[:2000])
        else:
            self.record("remote-config", "POST", self.app_id, st, UNKNOWN,
                        f"Remote Config HTTP {st}", url)

    # --- concurrency helper ---------------------------------------------------
    def _fanout(self, arg_tuples, fn):
        with cf.ThreadPoolExecutor(max_workers=self.jobs) as ex:
            list(ex.map(lambda a: fn(*a), arg_tuples))


def _json_non_empty(body):
    try:
        v = json.loads(body)
    except Exception:
        return False
    if isinstance(v, (dict, list)):
        return len(v) > 0
    return v is not None


def _read_wordlist(path):
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
    return out


# --- reporting ----------------------------------------------------------------
CHECK_ORDER = [
    ("hosting", "check_hosting"),
    ("hosting-paths", "check_hosting_paths"),
    ("identity-toolkit", "check_identity_toolkit"),
    ("remote-config", "check_remote_config"),
    ("firestore", "check_firestore"),
    ("storage", "check_storage"),
    ("rtdb", "check_rtdb"),
    ("cloud-run", "check_cloud_run"),
    ("cloud-functions", "check_cloud_functions"),
    ("api-docs", "check_api_docs"),
]


def to_json(scanner):
    return json.dumps({
        "project_id": scanner.project_id,
        "bucket": scanner.bucket,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "summary": {s: sum(1 for f in scanner.findings if f.severity == s)
                    for s in (VULN, OK, INFO, WARN, UNKNOWN)},
        "findings": [asdict(f) for f in scanner.findings],
    }, indent=2)


def to_html(scanner):
    bg = {VULN: "#fde8e8", OK: "#e8f5e9", INFO: "#e3f2fd",
          WARN: "#fff8e1", UNKNOWN: "#f3e5f5"}
    counts = {s: sum(1 for f in scanner.findings if f.severity == s)
              for s in (VULN, OK, INFO, WARN, UNKNOWN)}
    rows = []
    for f in scanner.findings:
        rows.append(
            f'<tr style="background:{bg[f.severity]}">'
            f"<td>{html.escape(f.module)}</td><td>{html.escape(f.action)}</td>"
            f"<td>{html.escape(str(f.target))}</td>"
            f"<td>{html.escape(str(f.status))}</td>"
            f"<td>{PREFIX[f.severity]}</td>"
            f"<td>{html.escape(f.message)}</td></tr>")
    return f"""<!doctype html><html><head><meta charset="utf-8">
<style>
body{{font-family:system-ui,sans-serif;margin:20px;color:#222}}
table{{border-collapse:collapse;width:100%;font-size:13px}}
th,td{{border:1px solid #ddd;padding:6px 8px;text-align:left}}
th{{background:#263238;color:#fff}}
.sum span{{display:inline-block;margin-right:14px;font-weight:600}}
</style></head><body>
<h2>GCP/Firebase recon — {html.escape(scanner.project_id)}</h2>
<p>bucket: <code>{html.escape(scanner.bucket)}</code> ·
generated {time.strftime("%Y-%m-%d %H:%M:%S")}</p>
<p class="sum">
<span style="color:#c62828">VULN {counts[VULN]}</span>
<span style="color:#2e7d32">OK {counts[OK]}</span>
<span style="color:#1565c0">INFO {counts[INFO]}</span>
<span style="color:#f9a825">WARN {counts[WARN]}</span>
<span style="color:#6a1b9a">UNKNOWN {counts[UNKNOWN]}</span></p>
<table><tr><th>Module</th><th>Action</th><th>Target</th><th>HTTP</th>
<th>Sev</th><th>Message</th></tr>
{''.join(rows)}
</table></body></html>"""


def send_email(scanner, to_addr, html_body):
    host = os.environ.get("SMTP_HOST", "localhost")
    port = int(os.environ.get("SMTP_PORT", "25"))
    user = os.environ.get("SMTP_USER", "")
    passwd = os.environ.get("SMTP_PASS", "")
    sender = os.environ.get("SMTP_FROM", user or "gcp-recon@localhost")
    vulns = sum(1 for f in scanner.findings if f.severity == VULN)

    msg = EmailMessage()
    msg["Subject"] = f"[gcp-recon] {scanner.project_id}: {vulns} findings"
    msg["From"] = sender
    msg["To"] = to_addr
    msg.set_content("HTML report attached; view in an HTML-capable client.")
    msg.add_alternative(html_body, subtype="html")

    with smtplib.SMTP(host, port, timeout=30) as s:
        if os.environ.get("SMTP_STARTTLS"):
            s.starttls()
        if user:
            s.login(user, passwd)
        s.send_message(msg)
    print(f"[*] Email sent to {to_addr} via {host}:{port}")


# --- cli ----------------------------------------------------------------------
def main(argv=None):
    p = argparse.ArgumentParser(
        description="GCP/Firebase unauthenticated-exposure recon")
    p.add_argument("project_id")
    p.add_argument("-b", "--bucket", default="")
    p.add_argument("-w", "--wordlist", default="")
    p.add_argument("-k", "--apikey", default=os.environ.get("FIREBASE_API_KEY", ""))
    p.add_argument("-a", "--appid", default=os.environ.get("FIREBASE_APP_ID", ""))
    p.add_argument("-j", "--jobs", type=int, default=5)
    p.add_argument("-t", "--timeout", type=int, default=10)
    p.add_argument("--exclude", default="",
                   help=f"comma list of modules to skip: {','.join(MODULES)}")
    p.add_argument("--only", default="", help="comma list; run only these modules")
    p.add_argument("--json", metavar="FILE", help="write JSON report ('-' = stdout)")
    p.add_argument("--html", metavar="FILE", help="write HTML report ('-' = stdout)")
    p.add_argument("--email", metavar="ADDR",
                   help="email HTML report (SMTP_* env vars)")
    p.add_argument("--no-color", action="store_true")
    args = p.parse_args(argv)

    bucket = args.bucket or f"{args.project_id}.firebasestorage.app"
    if args.wordlist and not os.path.isfile(args.wordlist):
        p.error(f"wordlist not found: {args.wordlist}")

    color = (not args.no_color and sys.stdout.isatty()
             and not os.environ.get("NO_COLOR"))
    sc = Scanner(args.project_id, bucket, args.apikey, args.appid,
                 args.wordlist, args.timeout, max(1, args.jobs), color)

    excluded = {m.strip() for m in args.exclude.split(",") if m.strip()}
    only = {m.strip() for m in args.only.split(",") if m.strip()}
    for name, meth in CHECK_ORDER:
        if only and name not in only:
            continue
        if name in excluded:
            print(f"[*] Skipping {name}")
            continue
        getattr(sc, meth)()

    if args.json:
        out = to_json(sc)
        _emit(args.json, out)
    if args.html:
        _emit(args.html, to_html(sc))
    if args.email:
        send_email(sc, args.email, to_html(sc))

    return 2 if any(f.severity == VULN for f in sc.findings) else 0


def _emit(dest, text):
    if dest == "-":
        print(text)
    else:
        with open(dest, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"[*] wrote {dest}")


if __name__ == "__main__":
    sys.exit(main())
