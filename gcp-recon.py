#!/usr/bin/env python3
"""GCP / Firebase unauthenticated-exposure recon.

Stdlib only (urllib/concurrent/smtplib) so it runs anywhere cron does.
Every check appends structured Findings; output goes to stdout (colored),
--json, and/or --html, and can be emailed straight from cron.
"""

import argparse
import concurrent.futures as cf
import configparser
import html
import re
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
DOC_PATHS = ["/swagger.json", "/openapi.json", "/api-docs", "/docs",
             "/v1/swagger.json", "/v1/openapi.json"]
# Firestore supports multiple named databases; only "(default)" gets the full
# wordlist+CRUD sweep, the rest just get a cheap root read.
FIRESTORE_DBS = ["prod", "staging", "dev", "test", "qa"]
# Newer RTDB instances live on regional *.firebasedatabase.app hosts.
RTDB_REGIONS = ["us-central1", "europe-west1", "asia-southeast1"]
# Endpoints that return usable data only when an AIza key is unrestricted for
# that API -> proves the key is abusable (billing). status "OK"/"ZERO_RESULTS"
# = works; "REQUEST_DENIED" = restricted/not enabled.
APIKEY_ABUSE = {
    "maps-geocode": "https://maps.googleapis.com/maps/api/geocode/json?address=NYC&key=",
    "maps-places": ("https://maps.googleapis.com/maps/api/place/findplacefromtext/json"
                    "?input=cafe&inputtype=textquery&key="),
    "maps-directions": ("https://maps.googleapis.com/maps/api/directions/json"
                        "?origin=NYC&destination=Boston&key="),
    "maps-timezone": ("https://maps.googleapis.com/maps/api/timezone/json"
                      "?location=40,-74&timestamp=0&key="),
}

# Secrets to hunt for in the base page + referenced JS. Google/Firebase/Gemini
# all issue AIza-prefixed keys, so google-api-key covers Gemini too.
SECRET_RE = {
    "google-api-key": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    "gcp-oauth-client": re.compile(r"[0-9]+-[0-9a-z]+\.apps\.googleusercontent\.com"),
    "gcp-service-account": re.compile(r'"type"\s*:\s*"service_account"'),
    "private-key-block": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    "aws-access-key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "slack-token": re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
    "stripe-secret": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    "github-token": re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}"),
    "openai-key": re.compile(r"sk-[A-Za-z0-9]{20,}"),
    # generic capture is last so specific patterns claim their values first; the
    # value is group(1) and gets entropy-filtered (see _plausible_secret).
    "generic-secret": re.compile(
        r"""(?i)(?:api[_-]?key|secret|token|password|passwd)\s*[:=]\s*"""
        r"""['"]([0-9A-Za-z_\-\.]{16,})['"]"""),
}
# Firebase/Google client keys are public by design; a bare AIza key can't be
# told apart from a sensitive Gemini/Maps key by format, so it's WARN (review
# restrictions), not VULN. generic-secret is low-confidence -> WARN too.
SECRET_SEV = {"google-api-key": WARN, "generic-secret": WARN}
_KEBAB_WORDS = re.compile(r"[a-z]+([-_][a-z]+)+\Z")
SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
MAX_SCRIPTS = 30   # ponytail: cap per host; Angular lazy chunks aren't in index.html anyway


def _plausible_secret(v):
    """Reject minified-SDK noise: kebab/snake error codes ('missing-password',
    'invalid-credential') and any value without a digit — real keys/tokens are
    high-entropy and almost always contain digits."""
    if _KEBAB_WORDS.match(v):
        return False
    return any(c.isdigit() for c in v)

MODULES = ["hosting", "hosting-secrets", "identity-toolkit", "remote-config",
           "firestore", "storage", "rtdb", "cloud-run", "cloud-functions",
           "api-docs", "apikey-abuse"]


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
                # This reserved path is public by design; the Firebase web config
                # is not secret on its own. Note databaseURL -> the RTDB module
                # actually tests whether that DB is open.
                self.record("hosting", "GET", url, st, INFO,
                            f"Firebase client config in init.js (public by design): {url}",
                            url, body)
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

    def check_hosting_secrets(self):
        self.banner("Firebase Hosting — base page + JS secret scan")
        hosts = [f"https://{self.project_id}.web.app",
                 f"https://{self.project_id}.firebaseapp.com"]
        seen = set()          # (pattern, value) so the same hit is one finding
        specific_vals = set()  # values claimed by specific patterns, to skip in generic
        for host in hosts:
            st, body = self.http("GET", host)
            if st != 200 or not body:
                self.log(f"{host} base page HTTP {st}")
                continue
            # Base HTML plus every same-page-referenced script, resolved absolute.
            contents = [(host, body)]
            srcs = SCRIPT_SRC_RE.findall(body)[:MAX_SCRIPTS]
            for src in srcs:
                url = urllib.parse.urljoin(host + "/", src)
                if not url.startswith(("http://", "https://")):
                    continue
                s2, b2 = self.http("GET", url)
                if s2 == 200 and b2:
                    contents.append((url, b2))
            self.log(f"{host}: scanned base page + {len(contents) - 1} script(s)")
            for src_url, text in contents:
                for name, rx in SECRET_RE.items():
                    for m in rx.finditer(text):
                        if name == "generic-secret":
                            val = m.group(1)
                            # skip dup of a specific pattern + SDK error-code noise
                            if val in specific_vals or not _plausible_secret(val):
                                continue
                        else:
                            val = m.group(0)
                            specific_vals.add(val)
                        if (name, val) in seen:
                            continue
                        seen.add((name, val))
                        sev = SECRET_SEV.get(name, VULN)
                        self.record("hosting-secrets", "SECRET", name, st, sev,
                                    f"{name}: {val[:80]} @ {src_url}", src_url, val)
        if not seen:
            self.log("No secrets found in hosting content")

    def check_api_docs(self):
        self.banner("API Gateway / OpenAPI discovery")
        hosts = [f"https://{self.project_id}.web.app",
                 f"https://{self.project_id}.firebaseapp.com"]

        def probe(host, path):
            # Angular/SPA hosting serves index.html (HTTP 200) for every path via
            # its catch-all rewrite, so a 200 means nothing. Only flag when the
            # body actually parses as an OpenAPI/Swagger document.
            url = host + path
            st, body = self.http("GET", url)
            if st != 200:
                return
            try:
                j = json.loads(body)
            except Exception:
                return
            if isinstance(j, dict) and (j.get("openapi") or j.get("swagger")
                                        or j.get("paths")):
                self.record("api-docs", "GET", url, st, VULN,
                            f"Valid OpenAPI/Swagger doc: {url}", url, body[:2000])

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
        # Newer default DBs live on regional *.firebasedatabase.app hosts.
        hosts += [f"https://{self.project_id}-default-rtdb.{r}.firebasedatabase.app"
                  for r in RTDB_REGIONS]
        doc_id = f"audit_{int(time.time())}_{os.getpid()}"
        found = False
        for host in hosts:
            # READ decides whether this host has a DB at all; a 404/connection
            # error (regional host that doesn't exist) skips the rest -> no noise.
            st, body = self.http("GET", host + "/.json")
            if st not in (200, 401, 403):
                continue
            found = True
            self.log(host)
            try:
                j = json.loads(body)
            except Exception:
                j = None
            if st in (401, 403) or (isinstance(j, dict) and j.get("error") == "Permission denied"):
                self.record("rtdb", "READ", host, st, OK, "RTDB read blocked", host)
            elif j not in (None, {}):
                self.record("rtdb", "READ", host, st, VULN,
                            "POSSIBLE EXPOSURE: RTDB returned public data", host,
                            body[:2000])
            else:
                self.record("rtdb", "READ", host, st, UNKNOWN,
                            "RTDB returned empty/null", host)

            # Security rules read: normally 401, a 200 leaks the ruleset.
            st, body = self.http("GET", host + "/.settings/rules.json")
            if st == 200 and _json_non_empty(body):
                self.record("rtdb", "RULES", host, st, VULN,
                            "RTDB security rules readable unauthenticated", host,
                            body[:2000])

            # WRITE / UPDATE / DELETE
            path = f"{host}/security_audit_tmp/{doc_id}.json"
            for action, method, data in (("WRITE", "PUT", {"security_test": True}),
                                         ("UPDATE", "PATCH", {"updated": True}),
                                         ("DELETE", "DELETE", None)):
                st, _ = self.http(method, path, data)
                self.record("rtdb", action, host, st,
                            VULN if st == 200 else OK if st in (401, 403) else UNKNOWN,
                            f"RTDB unauthenticated {action} HTTP {st}", path)
        if not found:
            self.log("No reachable RTDB instance on any known/regional host")

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
        """Firestore is the noisy module: only public (HTTP 200) operations are
        recorded, so a huge wordlist doesn't bloat the report with OK/blocked
        rows. LIST reads first; the write ops run only if the doc is reachable."""
        st, _ = self.http("GET", f"{base}/{collection}?pageSize=1")
        if st == 200:
            self.record("firestore", "LIST", collection, st, VULN,
                        f"PUBLIC LIST/READ: {collection}", f"{base}/{collection}")

        doc_id = f"audit_{int(time.time())}_{os.getpid()}"
        doc = f"{base}/{collection}/{doc_id}"
        payload = {"fields": {"security_test": {"booleanValue": True},
                              "operation": {"stringValue": "unauth_test"}}}
        ops = [
            ("CREATE", "POST", f"{base}/{collection}?documentId={doc_id}", payload),
            ("READ", "GET", doc, None),
            ("UPDATE", "PATCH", f"{doc}?updateMask.fieldPaths=operation", payload),
            ("DELETE", "DELETE", doc, None),
        ]
        for action, method, url, data in ops:
            st, _ = self.http(method, url, data)
            if st == 200:
                self.record("firestore", action, collection, st, VULN,
                            f"PUBLIC {action}: {collection}", url)

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

        cols = ["security_audit_tmp"]
        if self.wordlist:
            wl = _read_wordlist(self.wordlist)
            if not wl:
                self.record("firestore", "WORDLIST", self.wordlist, None, WARN,
                            "Wordlist empty after filtering", self.wordlist)
            cols = wl + cols
        else:
            self.log("No --wordlist: only testing unauthenticated CRUD on a temp collection")

        self.log(f"Testing {len(cols)} collection(s); reporting only public ones...")
        before = sum(1 for f in self.findings if f.module == "firestore")
        self._fanout([(c,) for c in cols], lambda c: self._firestore_crud(base, c))
        public = sum(1 for f in self.findings if f.module == "firestore") - before
        self.log(f"Firestore: {len(cols)} tested, {public} public operation(s) found")

        # Named databases beyond (default): cheap root read each, report only 200.
        def probe_db(db):
            u = (f"https://firestore.googleapis.com/v1/projects/{self.project_id}"
                 f"/databases/{db}/documents")
            st, body = self.http("GET", u)
            if st == 200 and _json_non_empty(body):
                self.record("firestore", "DB", db, st, VULN,
                            f"PUBLIC named database: {db}", u, body[:2000])

        self._fanout([(db,) for db in FIRESTORE_DBS], probe_db)

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

        # Account enumeration via createAuthUri: if the response reveals whether
        # an identifier is registered, emails can be enumerated with the key.
        url = f"{it}/v1/accounts:createAuthUri?key={k}"
        st, body = self.http("POST", url,
                             {"identifier": "gcp-recon-probe@example.com",
                              "continueUri": "http://localhost"})
        if st == 200 and '"registered"' in body:
            self.record("identity-toolkit", "POST", "account-enumeration", st, VULN,
                        "Account enumeration possible via createAuthUri", url, body[:500])
        elif st in (400, 401, 403):
            self.record("identity-toolkit", "POST", "account-enumeration", st, OK,
                        "createAuthUri blocked / enumeration protected", url)
        else:
            self.record("identity-toolkit", "POST", "account-enumeration", st, UNKNOWN,
                        f"createAuthUri HTTP {st}", url)

        # Email/password self-registration (distinct from anonymous). Creates a
        # real account -> cleaned up. Probe address uses reserved example.com.
        url = f"{it}/v1/accounts:signUp?key={k}"
        probe_email = f"gcp-recon-{int(time.time())}@example.com"
        st, body = self.http("POST", url, {"email": probe_email,
                                           "password": "Aud1t-Pr0be!x9",
                                           "returnSecureToken": True})
        tok = ""
        try:
            tok = json.loads(body).get("idToken", "")
        except Exception:
            pass
        if st == 200 and tok:
            self.record("identity-toolkit", "POST", "email-signup", st, WARN,
                        "Email/password self-registration ENABLED", url)
            self.http("POST", f"{it}/v1/accounts:delete?key={k}", {"idToken": tok})
        elif "ADMIN_ONLY_OPERATION" in body or st in (400, 403):
            self.record("identity-toolkit", "POST", "email-signup", st, OK,
                        "Email/password signup blocked/admin-only", url)
        else:
            self.record("identity-toolkit", "POST", "email-signup", st, UNKNOWN,
                        f"Email signup HTTP {st}", url)

        # sendOobCode reachability (password reset). Probe is a non-existent
        # address at reserved example.com, so no real user is emailed.
        url = f"{it}/v1/accounts:sendOobCode?key={k}"
        st, body = self.http("POST", url,
                             {"requestType": "PASSWORD_RESET",
                              "email": "gcp-recon-probe@example.com"})
        if st == 200:
            self.record("identity-toolkit", "POST", "oob-email-abuse", st, WARN,
                        "sendOobCode reachable with API key (email-abuse surface)", url)
        elif st in (400, 401, 403):
            self.record("identity-toolkit", "POST", "oob-email-abuse", st, OK,
                        "sendOobCode blocked", url)
        else:
            self.record("identity-toolkit", "POST", "oob-email-abuse", st, UNKNOWN,
                        f"sendOobCode HTTP {st}", url)

        # webConfig recovery: reconstructs the full Firebase config from appId+key.
        if self.app_id:
            url = (f"https://firebase.googleapis.com/v1alpha/projects/-/apps/"
                   f"{self.app_id}/webConfig")
            st, body = self.http("GET", url + f"?key={k}")
            if st == 200 and _json_non_empty(body):
                self.record("identity-toolkit", "GET", "webconfig-recovery", st, INFO,
                            "Firebase webConfig recoverable from appId+apiKey", url,
                            body[:1000])

    def check_apikey_abuse(self):
        self.banner("Google API key restriction / abuse")
        # Candidate keys: the configured one plus any AIza key found in hosting JS.
        keys = {self.api_key} | {
            f.detail for f in self.findings
            if f.module == "hosting-secrets" and f.target == "google-api-key"}
        keys = sorted(k for k in keys if k)
        if not keys:
            self.log("No API key available to test (use -k or run hosting-secrets)")
            return
        self.log(f"Testing {len(keys)} key(s) against {len(APIKEY_ABUSE)} Google APIs")

        def probe(key, name, base):
            st, body = self.http("GET", base + urllib.parse.quote(key, safe=""))
            usable = False
            try:
                usable = json.loads(body).get("status") in ("OK", "ZERO_RESULTS")
            except Exception:
                usable = False
            short = key[:14] + "..."
            if usable:
                self.record("apikey-abuse", name, short, st, VULN,
                            f"API key UNRESTRICTED for {name} (billable): {short}", base)
            elif st == 200:  # REQUEST_DENIED / restricted
                self.record("apikey-abuse", name, short, st, OK,
                            f"{name} restricted for {short}", base)

        self._fanout([(key, name, base) for key in keys
                      for name, base in APIKEY_ABUSE.items()], probe)

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
    ("hosting-secrets", "check_hosting_secrets"),
    ("identity-toolkit", "check_identity_toolkit"),
    ("remote-config", "check_remote_config"),
    ("firestore", "check_firestore"),
    ("storage", "check_storage"),
    ("rtdb", "check_rtdb"),
    ("cloud-run", "check_cloud_run"),
    ("cloud-functions", "check_cloud_functions"),
    ("api-docs", "check_api_docs"),
    ("apikey-abuse", "check_apikey_abuse"),   # after hosting-secrets: reuses found keys
]


# Spanish problem/consequence descriptions shown in the report's "Descripción"
# column. Keyed by (module, subkey); subkey is target/action depending on module
# (see _describe). Falls back to a module-level text.
FINDING_DESC = {
    ("identity-toolkit", "anonymous-signup"):
        "Registro anónimo habilitado: cualquiera obtiene un idToken válido sin "
        "credenciales. Permite pasar reglas que solo exigen estar autenticado "
        "(request.auth != null), crear datos y abusar de cuotas.",
    ("identity-toolkit", "account-enumeration"):
        "createAuthUri revela si un correo está registrado y con qué proveedor. "
        "Permite enumerar usuarios válidos para phishing o credential stuffing.",
    ("identity-toolkit", "email-signup"):
        "Auto-registro con email/contraseña habilitado: se pueden crear cuentas "
        "arbitrarias sin aprobación (acceso a funciones de usuario, spam, abuso). "
        "A veces es intencional; confirmar si el registro público es deseado.",
    ("identity-toolkit", "oob-email-abuse"):
        "sendOobCode es alcanzable solo con la API key: permite disparar correos "
        "de reset/verificación a direcciones arbitrarias usando la reputación del "
        "dominio del proyecto para spam o phishing.",
    ("identity-toolkit", "admin-config"):
        "Configuración administrativa de Identity Platform accesible solo con la "
        "API key. Expone proveedores, dominios y ajustes que deberían requerir "
        "credenciales de administrador.",
    ("identity-toolkit", "legacy-config"):
        "El endpoint legacy getProjectConfig responde solo con la API key y filtra "
        "la configuración de auth (dominios autorizados, proveedores, a veces "
        "secretos OAuth). Facilita el reconocimiento del proyecto.",
    ("identity-toolkit", "account-list"):
        "El listado de cuentas (accounts:batchGet) sería accesible: expondría datos "
        "de usuarios (emails, UIDs). Crítico si responde 200.",
    ("identity-toolkit", "oidc-idp"):
        "La configuración de proveedores OIDC es accesible solo con la API key, "
        "revelando IdPs y posibles clientId/secret.",
    ("identity-toolkit", "saml-idp"):
        "La configuración de proveedores SAML es accesible solo con la API key, "
        "revelando IdPs y metadatos de federación.",
    ("identity-toolkit", "default-idp"):
        "La configuración de proveedores por defecto es accesible solo con la API "
        "key, revelando qué métodos de login están habilitados.",
    ("identity-toolkit", "recaptcha-config"):
        "Configuración de reCAPTCHA (normalmente pública por diseño del cliente). "
        "Informativo.",
    ("identity-toolkit", "webconfig-recovery"):
        "Con appId + apiKey se reconstruye la configuración completa de Firebase. "
        "Es config de cliente (pública por diseño), útil para reconocimiento.",
    ("hosting-secrets", "google-api-key"):
        "Clave de API de Google embebida en el JS del cliente. Las claves web de "
        "Firebase son públicas por diseño, pero si es de Maps/Gemini u otra API sin "
        "restricciones puede abusarse (facturación). Ver módulo apikey-abuse.",
    ("hosting-secrets", "generic-secret"):
        "Posible secreto codificado en el bundle (patrón api_key/secret/token/"
        "password). Confianza baja: verificar si es credencial real o constante del "
        "framework.",
    ("hosting-secrets", "private-key-block"):
        "Bloque de clave privada (PEM) expuesto en el cliente. Credencial crítica: "
        "permite suplantar servicios o firmar tokens. Rotar de inmediato.",
    ("hosting-secrets", "gcp-service-account"):
        "Posible JSON de cuenta de servicio de GCP expuesto: credencial crítica que "
        "otorga acceso autenticado al proyecto. Rotar de inmediato.",
    ("firestore", "ROOT"):
        "La raíz de Firestore devuelve datos sin autenticación: las reglas permiten "
        "lectura pública, exponiendo datos potencialmente sensibles.",
    ("firestore", "LIST"):
        "Colección de Firestore legible sin autenticación: las reglas permiten "
        "lectura pública de sus documentos.",
    ("firestore", "READ"):
        "Documento de Firestore legible sin autenticación.",
    ("firestore", "CREATE"):
        "Escritura en Firestore sin autenticación: cualquiera puede insertar "
        "documentos (contenido malicioso, envenenamiento de datos, abuso de cuota).",
    ("firestore", "UPDATE"):
        "Modificación en Firestore sin autenticación: cualquiera puede alterar "
        "documentos existentes.",
    ("firestore", "DELETE"):
        "Borrado en Firestore sin autenticación: destrucción de datos por cualquiera.",
    ("firestore", "DB"):
        "Base de datos Firestore nombrada (no la default) accesible públicamente.",
    ("rtdb", "READ"):
        "Realtime Database legible sin autenticación: exposición completa de datos.",
    ("rtdb", "WRITE"):
        "Escritura en Realtime Database sin autenticación: manipulación/inyección "
        "de datos por cualquiera.",
    ("rtdb", "UPDATE"):
        "Modificación en Realtime Database sin autenticación.",
    ("rtdb", "DELETE"):
        "Borrado en Realtime Database sin autenticación: destrucción de datos.",
    ("rtdb", "RULES"):
        "Reglas de seguridad de RTDB legibles sin autenticación: revelan la lógica "
        "de acceso y facilitan encontrar rutas abiertas.",
    ("storage", "LIST"):
        "Listado del bucket sin autenticación: expone nombres de objetos y estructura.",
    ("storage", "WRITE"):
        "Subida de objetos al bucket sin autenticación: alojar contenido arbitrario "
        "(malware/phishing) y consumir almacenamiento a costa del proyecto.",
    ("storage", "GET"):
        "Descarga de objetos del bucket sin autenticación.",
    ("storage", "DEL"):
        "Borrado de objetos del bucket sin autenticación: destrucción de datos.",
}
MODULE_DESC = {
    "hosting":
        "init.js de Firebase Hosting es público por diseño y contiene la config de "
        "cliente (apiKey, projectId...). No es secreto en sí; el riesgo depende de "
        "si RTDB/Firestore/Storage tienen reglas abiertas.",
    "hosting-secrets":
        "Credencial de terceros expuesta en el contenido del cliente. Puede permitir "
        "acceso no autorizado al servicio correspondiente; rotar y mover a backend.",
    "remote-config":
        "Remote Config devuelve datos con appId+apiKey (esperado). Puede exponer "
        "flags de funcionalidades o secretos codificados en parámetros.",
    "cloud-run":
        "Host de Cloud Run candidato/alcanzable. Verificar si el servicio permite "
        "invocación sin autenticar (allUsers con roles/run.invoker).",
    "cloud-functions":
        "Cloud Function candidata alcanzable. Verificar si permite invocación sin "
        "autenticación.",
    "api-docs":
        "Documento OpenAPI/Swagger público: expone la superficie de la API (rutas, "
        "parámetros) y facilita ataques dirigidos.",
    "apikey-abuse":
        "Clave de API de Google sin restricciones para esta API: cualquiera puede "
        "usarla y generar cargos de facturación en el proyecto. Restringir por "
        "referrer HTTP / API / IP.",
}


def _describe(f):
    if f.module == "storage":
        sub = f.action.split("_")[0]
    elif f.module in ("firestore", "rtdb"):
        sub = f.action
    else:
        sub = f.target
    return FINDING_DESC.get((f.module, sub)) or MODULE_DESC.get(f.module, "")


def _counts(findings):
    return {s: sum(1 for f in findings if f.severity == s)
            for s in (VULN, OK, INFO, WARN, UNKNOWN)}


def to_json(scanners):
    all_findings = [f for sc in scanners for f in sc.findings]
    return json.dumps({
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "summary": _counts(all_findings),
        "targets": [{
            "project_id": sc.project_id,
            "bucket": sc.bucket,
            "summary": _counts(sc.findings),
            "findings": [asdict(f) for f in sc.findings],
        } for sc in scanners],
    }, indent=2)


def _sum_line(counts):
    return (f'<span style="color:#c62828">VULN {counts[VULN]}</span>'
            f'<span style="color:#2e7d32">OK {counts[OK]}</span>'
            f'<span style="color:#1565c0">INFO {counts[INFO]}</span>'
            f'<span style="color:#f9a825">WARN {counts[WARN]}</span>'
            f'<span style="color:#6a1b9a">UNKNOWN {counts[UNKNOWN]}</span>')


def to_html(scanners):
    bg = {VULN: "#fde8e8", OK: "#e8f5e9", INFO: "#e3f2fd",
          WARN: "#fff8e1", UNKNOWN: "#f3e5f5"}
    order = [name for name, _ in CHECK_ORDER]

    def rows(findings):
        return ''.join(
            f'<tr style="background:{bg[f.severity]}">'
            f"<td>{html.escape(f.action)}</td>"
            f"<td>{html.escape(str(f.target))}</td>"
            f"<td>{html.escape(str(f.status))}</td>"
            f"<td>{PREFIX[f.severity]}</td>"
            f"<td>{html.escape(f.message)}</td>"
            f"<td>{html.escape(_describe(f))}</td></tr>" for f in findings)

    sections = []
    for sc in scanners:
        by_mod = {}
        for f in sc.findings:
            by_mod.setdefault(f.module, []).append(f)
        mods = ([m for m in order if m in by_mod]
                + [m for m in by_mod if m not in order])
        subs = []
        for m in mods:
            fs = by_mod[m]
            subs.append(
                f'<details open><summary><b>{html.escape(m)}</b> '
                f'<span class="sum">{_sum_line(_counts(fs))}</span></summary>'
                "<table><tr><th>Action</th><th>Target</th><th>HTTP</th>"
                "<th>Sev</th><th>Message</th><th>Descripción</th></tr>"
                f"{rows(fs)}</table></details>")
        body = ''.join(subs) or "<p><i>no findings</i></p>"
        sections.append(
            f'<section><h3>{html.escape(sc.project_id)} '
            f"<small>({html.escape(sc.bucket)})</small></h3>"
            f'<p class="sum">{_sum_line(_counts(sc.findings))}</p>{body}</section>')

    total = _counts([f for sc in scanners for f in sc.findings])
    return f"""<!doctype html><html><head><meta charset="utf-8">
<style>
body{{font-family:system-ui,sans-serif;margin:20px;color:#222}}
section{{border-top:3px solid #263238;margin-top:28px;padding-top:4px}}
h3{{margin-bottom:2px}}
details{{margin:8px 0 8px 8px}}
summary{{cursor:pointer;padding:4px 0}}
table{{border-collapse:collapse;width:100%;font-size:13px;margin:6px 0 14px}}
th,td{{border:1px solid #ddd;padding:6px 8px;text-align:left}}
th{{background:#263238;color:#fff}}
.sum span{{display:inline-block;margin-right:12px;font-weight:600}}
</style></head><body>
<h2>GCP/Firebase recon — {len(scanners)} target(s)</h2>
<p>generated {time.strftime("%Y-%m-%d %H:%M:%S")}</p>
<p class="sum">TOTAL: {_sum_line(total)}</p>
{''.join(sections)}
</body></html>"""


# Email clients (Gmail) strip <style> and don't render <details>, so the email
# report is built with table layout and inline styles only.
_SEV = {VULN: ("#c62828", "#fff"), OK: ("#2e7d32", "#fff"),
        INFO: ("#1565c0", "#fff"), WARN: ("#f9a825", "#3b2f00"),
        UNKNOWN: ("#6a1b9a", "#fff")}
_ROW_BG = {VULN: "#fdecea", OK: "#edf6ed", INFO: "#e9f1fb",
           WARN: "#fff7e0", UNKNOWN: "#f4eaf8"}
_TD = "padding:6px 9px;border-bottom:1px solid #ececec;color:#222;vertical-align:top"
_FONT = "font-family:Arial,Helvetica,sans-serif"


def _chips(counts, force=False):
    out = []
    for s in (VULN, OK, INFO, WARN, UNKNOWN):
        n = counts[s]
        if not n and not force:
            continue
        bg, fg = _SEV[s]
        out.append(f'<span style="display:inline-block;background:{bg};color:{fg};'
                   f'border-radius:11px;padding:2px 10px;{_FONT};font-size:11px;'
                   f'font-weight:700;margin:0 5px 5px 0">{s.upper()} {n}</span>')
    return ''.join(out) or ('<span style="color:#888;font-size:12px;'
                            f'{_FONT}">no findings</span>')


def to_html_email(scanners):
    total = _counts([f for sc in scanners for f in sc.findings])
    order = [n for n, _ in CHECK_ORDER]
    th = (f'<th style="background:#37474f;color:#fff;{_FONT};font-size:12px;'
          'text-align:left;padding:7px 9px">')

    cards = []
    for sc in scanners:
        by_mod = {}
        for f in sc.findings:
            by_mod.setdefault(f.module, []).append(f)
        mods = ([m for m in order if m in by_mod]
                + [m for m in by_mod if m not in order])
        subs = []
        for m in mods:
            fs = by_mod[m]
            trs = []
            for f in fs:
                bg, fg = _SEV[f.severity]
                trs.append(
                    f'<tr style="background:{_ROW_BG[f.severity]}">'
                    f'<td style="{_TD};font-size:12px;white-space:nowrap">{html.escape(f.action)}</td>'
                    f'<td style="{_TD};font-size:12px">{html.escape(str(f.target))}</td>'
                    f'<td style="{_TD};font-size:12px;text-align:center">{html.escape(str(f.status))}</td>'
                    f'<td style="{_TD};text-align:center"><span style="background:{bg};'
                    f'color:{fg};border-radius:4px;padding:1px 6px;font-size:10px;'
                    f'font-weight:700;{_FONT}">{f.severity.upper()}</span></td>'
                    f'<td style="{_TD};font-size:12px;word-break:break-word">{html.escape(f.message)}</td>'
                    f'<td style="{_TD};font-size:12px;color:#444">{html.escape(_describe(f))}</td></tr>')
            subs.append(
                f'<div style="margin:16px 0 6px">'
                f'<span style="{_FONT};font-weight:700;font-size:14px;color:#263238">'
                f'{html.escape(m)}</span>&nbsp;&nbsp;{_chips(_counts(fs))}</div>'
                '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
                'style="border-collapse:collapse;width:100%">'
                f'<tr>{th}Action</th>{th}Target</th>{th}HTTP</th>{th}Sev</th>'
                f'{th}Message</th>{th}Descripción</th></tr>'
                f'{"".join(trs)}</table>')
        body = ''.join(subs) or (f'<p style="{_FONT};color:#888;font-size:13px;'
                                 'margin:10px 0">No findings.</p>')
        cards.append(
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            'style="margin:0 0 22px;border:1px solid #dfe3e6;border-radius:8px">'
            '<tr><td style="background:#263238;padding:13px 18px;'
            'border-radius:8px 8px 0 0">'
            f'<div style="{_FONT};font-size:17px;font-weight:700;color:#fff">'
            f'{html.escape(sc.project_id)}</div>'
            f'<div style="{_FONT};font-size:12px;color:#90a4ae">'
            f'{html.escape(sc.bucket)}</div></td></tr>'
            f'<tr><td style="padding:14px 18px">'
            f'{_chips(_counts(sc.findings))}{body}</td></tr></table>')

    vulns = total[VULN]
    accent = "#c62828" if vulns else "#2e7d32"
    return f"""<!doctype html><html><body style="margin:0;background:#eef0f2;padding:0">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#eef0f2">
<tr><td align="center" style="padding:24px 12px">
<table role="presentation" width="720" cellpadding="0" cellspacing="0" style="width:720px;max-width:100%;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.12)">
<tr><td style="background:{accent};padding:22px 26px">
<div style="{_FONT};font-size:21px;font-weight:800;color:#fff">GCP / Firebase recon</div>
<div style="{_FONT};font-size:13px;color:#ffffffcc;margin-top:3px">{len(scanners)} target(s) · {time.strftime("%Y-%m-%d %H:%M")} · <b>{vulns} VULN</b></div>
</td></tr>
<tr><td style="padding:18px 22px 6px">
<div style="{_FONT};font-size:12px;color:#555;font-weight:700;margin-bottom:6px">TOTAL</div>
{_chips(total, force=True)}</td></tr>
<tr><td style="padding:8px 22px 22px">{''.join(cards)}</td></tr>
</table>
<div style="{_FONT};font-size:11px;color:#9aa0a6;margin-top:12px">gcp-recon · automated scan</div>
</td></tr></table></body></html>"""


def load_config(path):
    """Read INI config. Explicit --config missing is an error; the default
    path being absent is fine (returns an empty parser)."""
    cfg = configparser.ConfigParser()
    if path and os.path.isfile(path):
        if os.name == "posix" and (os.stat(path).st_mode & 0o077):
            print(f"[!] warning: {path} is group/world-readable; chmod 600 it")
        cfg.read(path)
    return cfg


def send_email(scanners, to_addr, html_body, cfg):
    """SMTP settings come from the [smtp] config section, falling back to
    SMTP_* env vars, so cron never needs secrets on its command line."""
    smtp = cfg["smtp"] if cfg.has_section("smtp") else {}

    def val(key, default=""):
        v = smtp.get(key.lower(), os.environ.get(f"SMTP_{key}", default))
        return v.strip().strip('"').strip("'")   # tolerate quoted/padded values

    host = val("HOST", "localhost")
    port = int(val("PORT", "25"))
    user = val("USER")
    passwd = val("PASS")
    sender = val("FROM", user or "gcp-recon@localhost")
    starttls = str(val("STARTTLS")).lower() in ("1", "true", "yes")
    vulns = sum(1 for sc in scanners for f in sc.findings if f.severity == VULN)
    scope = (scanners[0].project_id if len(scanners) == 1
             else f"{len(scanners)} targets")

    recipients = [a.strip() for a in to_addr.split(",") if a.strip()]
    msg = EmailMessage()
    msg["Subject"] = f"[gcp-recon] {scope}: {vulns} VULN findings"
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)   # smtplib derives recipients from this header
    msg.set_content("HTML report attached; view in an HTML-capable client.")
    msg.add_alternative(html_body, subtype="html")

    try:
        with smtplib.SMTP(host, port, timeout=30) as s:
            if starttls:
                s.starttls()
            if user:
                s.login(user, passwd)
            s.send_message(msg)
        print(f"[*] Email sent to {len(recipients)} recipient(s) "
              f"({', '.join(recipients)}) via {host}:{port}")
    except smtplib.SMTPAuthenticationError:
        print(f"[!] SMTP auth rejected by {host}. For Gmail: enable 2FA and use a "
              "16-char App Password (https://myaccount.google.com/apppasswords), "
              "not your login password.", file=sys.stderr)
    except (smtplib.SMTPException, OSError) as e:
        print(f"[!] Email send failed: {e}", file=sys.stderr)


# --- cli ----------------------------------------------------------------------
def main(argv=None):
    p = argparse.ArgumentParser(
        description="GCP/Firebase unauthenticated-exposure recon")
    p.add_argument("project_id", nargs="?",
                   help="single target; omit when using --targets")
    p.add_argument("--targets", metavar="FILE",
                   help="JSON file: list of {project_id, apikey, appid, "
                        "bucket, wordlist} to scan in one run")
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
                   help="email HTML report; comma-separate for multiple recipients")
    p.add_argument("--config", default=os.path.expanduser("~/.config/gcp-recon.conf"),
                   metavar="FILE",
                   help="INI file with [smtp] secrets and optional [defaults]")
    p.add_argument("--no-color", action="store_true")
    args = p.parse_args(argv)

    cfg = load_config(args.config)
    d = cfg["defaults"] if cfg.has_section("defaults") else {}
    color = (not args.no_color and sys.stdout.isatty()
             and not os.environ.get("NO_COLOR"))

    # Build the target list. CLI flags/config act as fallbacks for any field a
    # target in --targets omits, so shared settings stay in one place.
    if args.targets:
        with open(args.targets, encoding="utf-8") as fh:
            targets = json.load(fh)
        if not isinstance(targets, list):
            p.error("--targets JSON must be a list of target objects")
    elif args.project_id:
        targets = [{"project_id": args.project_id}]
    else:
        p.error("give a project_id or --targets FILE")

    excluded = {m.strip() for m in args.exclude.split(",") if m.strip()}
    only = {m.strip() for m in args.only.split(",") if m.strip()}
    scanners = []

    for t in targets:
        pid = t.get("project_id")
        if not pid:
            print("[!] skipping target without project_id", file=sys.stderr)
            continue
        wordlist = t.get("wordlist") or args.wordlist or d.get("wordlist", "")
        if wordlist and not os.path.isfile(wordlist):
            print(f"[!] {pid}: wordlist not found: {wordlist}", file=sys.stderr)
            wordlist = ""
        bucket = t.get("bucket") or args.bucket or f"{pid}.firebasestorage.app"
        sc = Scanner(
            pid, bucket,
            t.get("apikey") or args.apikey or d.get("apikey", ""),
            t.get("appid") or args.appid or d.get("appid", ""),
            wordlist, args.timeout, max(1, args.jobs), color)
        for name, meth in CHECK_ORDER:
            if only and name not in only:
                continue
            if name in excluded:
                continue
            getattr(sc, meth)()
        scanners.append(sc)

    if args.json:
        _emit(args.json, to_json(scanners))
    if args.html:
        _emit(args.html, to_html(scanners))
    if args.email:
        send_email(scanners, args.email, to_html_email(scanners), cfg)

    all_findings = [f for sc in scanners for f in sc.findings]
    return 2 if any(f.severity == VULN for f in all_findings) else 0


def _emit(dest, text):
    if dest == "-":
        print(text)
    else:
        with open(dest, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"[*] wrote {dest}")


if __name__ == "__main__":
    sys.exit(main())
