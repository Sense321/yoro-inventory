#!/usr/bin/env python3
import http.server, urllib.request, urllib.parse, json, os, sys
import hashlib, hmac, base64, time, datetime, secrets
import smtplib, threading
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders as _email_encoders

# ── Configuration ─────────────────────────────────────────────────────────────
SHOPIFY_SHOP          = os.environ.get('SHOPIFY_SHOP',          'heyhoney-com.myshopify.com')
SHOPIFY_TOKEN         = os.environ.get('SHOPIFY_TOKEN',         '')   # fallback env var
SHOPIFY_CLIENT_ID     = os.environ.get('SHOPIFY_CLIENT_ID',     '')
SHOPIFY_CLIENT_SECRET = os.environ.get('SHOPIFY_CLIENT_SECRET', '')
SHOPIFY_SCOPES        = 'read_products,write_products,read_orders,write_orders,read_customers,write_customers,read_fulfillments,write_fulfillments,write_merchant_managed_fulfillment_orders'
SHOPIFY_VER           = '2025-04'
APP_URL               = os.environ.get('APP_URL', 'https://yoro-inventory-production.up.railway.app')
PORT                  = int(os.environ.get('PORT', 8765))
SECRET_KEY            = os.environ.get('SECRET_KEY', 'hhp-change-this-in-production-2026')
SMTP_HOST             = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT             = int(os.environ.get('SMTP_PORT', 587))
SMTP_USER             = os.environ.get('SMTP_USER', '')
SMTP_PASS             = os.environ.get('SMTP_PASS', '')
SMTP_FROM             = os.environ.get('SMTP_FROM', SMTP_USER)
DIR                   = os.path.dirname(os.path.abspath(__file__))
DATA_DIR              = os.environ.get('DATA_DIR', DIR)   # override on Railway to persistent volume
USERS_FILE            = os.path.join(DATA_DIR, 'hhp_users.json')
DB_FILE               = os.path.join(DATA_DIR, 'hhp_db.json')
TOKEN_FILE            = os.path.join(DATA_DIR, 'shopify_oauth_token.txt')
TOKEN_TTL             = 60 * 60 * 24 * 30  # 30 days

# ── Zoho Inventory configuration ──────────────────────────────────────────────
ZOHO_CLIENT_ID     = os.environ.get('ZOHO_CLIENT_ID',     '1000.HJJBMJEW8U0OGIB0EMVYU4819564LT')
ZOHO_CLIENT_SECRET = os.environ.get('ZOHO_CLIENT_SECRET', '708e8905721002ea858f507515b0867fd164ea5c19')
ZOHO_ORG_ID        = os.environ.get('ZOHO_ORG_ID',        '834798578')
ZOHO_REDIRECT_URI  = os.environ.get('ZOHO_REDIRECT_URI',  'https://www.srqfulfillment.com/zoho/callback')
ZOHO_TOKEN_FILE    = os.path.join(DATA_DIR, 'zoho_tokens.json')
ZOHO_API_BASE      = 'https://www.zohoapis.com/inventory/v1'
ZOHO_ACCOUNTS_URL  = 'https://accounts.zoho.com'

# ── Shopify OAuth token helpers ────────────────────────────────────────────────
def get_shopify_token():
    """Return best available Shopify token: file > db > env var."""
    if os.path.isfile(TOKEN_FILE):
        t = open(TOKEN_FILE).read().strip()
        if t: return t
    try:
        db = load_db()
        t = db.get('shopify', {}).get('accessToken', '')
        if t and t not in ('', 'server-managed'): return t
    except Exception:
        pass
    if SHOPIFY_TOKEN and SHOPIFY_TOKEN not in ('', 'unset'):
        return SHOPIFY_TOKEN
    return ''

def save_shopify_token(token):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(TOKEN_FILE, 'w') as f:
        f.write(token)
    # Mirror into db.shopify so the UI shows Connected
    try:
        db = load_db()
        sh = db.get('shopify', {})
        sh.update({'accessToken': token, 'connected': True,
                   'shop': SHOPIFY_SHOP,
                   'proxyUrl': '/.netlify/functions/shopify-proxy',
                   'apiVersion': SHOPIFY_VER})
        db['shopify'] = sh
        save_db(db)
    except Exception:
        pass

# ── Zoho token helpers ─────────────────────────────────────────────────────────
def load_zoho_tokens():
    # Primary: read from persistent db (survives redeploys)
    try:
        db = load_db()
        t = db.get('_zohoTokens')
        if t and t.get('refresh_token'):
            return t
    except Exception:
        pass
    # Fallback: local file (for local dev)
    if os.path.isfile(ZOHO_TOKEN_FILE):
        try:
            return json.load(open(ZOHO_TOKEN_FILE))
        except Exception:
            pass
    return {}

def save_zoho_tokens(tokens):
    # Save into db so tokens survive Railway redeploys
    try:
        db = load_db()
        db['_zohoTokens'] = tokens
        save_db(db)
    except Exception:
        pass
    # Also write local file as backup
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(ZOHO_TOKEN_FILE, 'w') as f:
            json.dump(tokens, f, indent=2)
    except Exception:
        pass

# ── QuickBooks Online ─────────────────────────────────────────────────────────
QB_SANDBOX_BASE = 'https://sandbox-quickbooks.api.intuit.com/v3/company'
QB_PROD_BASE    = 'https://quickbooks.api.intuit.com/v3/company'
QB_TOKEN_URL    = 'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer'
QB_AUTH_URL     = 'https://appcenter.intuit.com/connect/oauth2'

def qb_get_access_token(ig):
    """Return a valid QB access token, refreshing if needed. Updates ig creds in-place."""
    creds = ig.get('credentials', {})
    if creds.get('qbAccessToken') and creds.get('qbTokenExpiry', 0) > time.time() + 300:
        return creds['qbAccessToken']
    client_id     = creds.get('clientId', '')
    client_secret = creds.get('clientSecret', '')
    refresh_token = creds.get('refreshToken', '')
    if not all([client_id, client_secret, refresh_token]):
        raise ValueError('QuickBooks not fully authorized — missing clientId, clientSecret, or refreshToken')
    creds_b64 = base64.b64encode(f'{client_id}:{client_secret}'.encode()).decode()
    post_data = urllib.parse.urlencode({'grant_type': 'refresh_token', 'refresh_token': refresh_token}).encode()
    req = urllib.request.Request(QB_TOKEN_URL, data=post_data,
        headers={'Authorization': f'Basic {creds_b64}', 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'},
        method='POST')
    with urllib.request.urlopen(req, timeout=15) as r:
        tok = json.loads(r.read())
    if 'access_token' not in tok:
        raise ValueError(f'QB token refresh failed: {tok}')
    creds['qbAccessToken']  = tok['access_token']
    creds['refreshToken']   = tok.get('refresh_token', refresh_token)
    creds['qbTokenExpiry']  = int(time.time()) + tok.get('expires_in', 3600)
    return creds['qbAccessToken']

def get_zoho_access_token():
    """Return a valid Zoho access token, refreshing automatically if expired."""
    tokens = load_zoho_tokens()
    if not tokens.get('refresh_token'):
        raise ValueError('Zoho not connected. Authorize via /zoho/auth first.')
    # Refresh if expiring within 60 seconds
    if tokens.get('expires_at', 0) - time.time() < 60:
        refresh_req = urllib.request.Request(
            f'{ZOHO_ACCOUNTS_URL}/oauth/v2/token',
            data=urllib.parse.urlencode({
                'grant_type':    'refresh_token',
                'client_id':     ZOHO_CLIENT_ID,
                'client_secret': ZOHO_CLIENT_SECRET,
                'refresh_token': tokens['refresh_token'],
            }).encode(),
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            method='POST'
        )
        with urllib.request.urlopen(refresh_req, timeout=15) as r:
            tok = json.loads(r.read())
        if 'access_token' not in tok:
            raise ValueError(f'Zoho token refresh failed: {tok}')
        tokens['access_token'] = tok['access_token']
        tokens['expires_at']   = int(time.time()) + tok.get('expires_in', 3600)
        save_zoho_tokens(tokens)
    return tokens['access_token']

# ── Default admin user (created on first run if no users.json) ─────────────────
DEFAULT_USERS = [
    {
        "id": "1",
        "username": "admin",
        "passwordHash": hashlib.sha256(("hhpadmin2026" + "hhpsalt1").encode()).hexdigest(),
        "salt": "hhpsalt1",
        "name": "Administrator",
        "email": "",
        "role": "admin",
        "active": True,
        "permissions": {
            "canViewDashboard":      True,
            "canViewItems":          True,
            "canEditItems":          True,
            "canViewInventory":      True,
            "canEditInventory":      True,
            "canViewOrders":         True,
            "canEditOrders":         True,
            "canViewPurchases":      True,
            "canEditPurchases":      True,
            "canViewCustomers":      True,
            "canEditCustomers":      True,
            "canViewFinancials":     True,
            "canViewReports":        True,
            "canSyncIntegrations":   True,
            "canManageSettings":     True,
            "canDeletePermanently":  True,
            "canManageUsers":        True,
            "canPushNotifications":  True
        }
    }
]

# ── Auth helpers ───────────────────────────────────────────────────────────────
def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode()).hexdigest()

def make_token(user_id, role):
    expiry   = str(int(time.time()) + TOKEN_TTL)
    payload  = f"{user_id}|{role}|{expiry}"
    sig      = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    raw      = f"{payload}|{sig}"
    return base64.urlsafe_b64encode(raw.encode()).decode()

def verify_token(token):
    try:
        raw     = base64.urlsafe_b64decode(token.encode()).decode()
        *parts, sig = raw.split('|')
        payload = '|'.join(parts)
        expected = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        user_id, role, expiry = parts
        if int(time.time()) > int(expiry):
            return None
        return {'userId': user_id, 'role': role}
    except Exception:
        return None

def get_token_from_headers(headers):
    auth = headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        return auth[7:].strip()
    return None

# ── User store helpers ─────────────────────────────────────────────────────────
def load_users():
    if not os.path.isfile(USERS_FILE):
        save_users(DEFAULT_USERS)
        return DEFAULT_USERS
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def save_users(users):
    os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def find_user(username):
    for u in load_users():
        if u['username'].lower() == username.lower():
            return u
    return None

def find_user_by_id(uid):
    for u in load_users():
        if u['id'] == uid:
            return u
    return None

# ── DB store helpers ───────────────────────────────────────────────────────────
def load_db():
    if not os.path.isfile(DB_FILE):
        return {}
    with open(DB_FILE, 'r') as f:
        return json.load(f)

_db_lock = threading.Lock()
BACKUP_DIR  = os.path.join(DATA_DIR, 'backups')
DAILY_DIR   = os.path.join(DATA_DIR, 'backups', 'daily')
MAX_HOURLY  = 48   # ~2 days of hourly snapshots
MAX_DAILY   = 7    # 7 midnight snapshots (one week)

def _rotate_backups():
    """Keep only the most recent MAX_HOURLY hourly files."""
    try:
        files = sorted(
            [f for f in os.listdir(BACKUP_DIR) if f.startswith('hhp_db_')],
            reverse=True
        )
        for old in files[MAX_HOURLY:]:
            try:
                os.remove(os.path.join(BACKUP_DIR, old))
            except Exception:
                pass
    except Exception:
        pass

def _rotate_daily_backups():
    """Keep only the most recent MAX_DAILY daily files, delete the oldest."""
    try:
        files = sorted(
            [f for f in os.listdir(DAILY_DIR) if f.startswith('daily_')],
            reverse=True
        )
        for old in files[MAX_DAILY:]:
            try:
                os.remove(os.path.join(DAILY_DIR, old))
            except Exception:
                pass
    except Exception:
        pass

def _midnight_backup():
    """Write a full daily backup, keep 7 copies, delete the oldest."""
    import shutil
    os.makedirs(DAILY_DIR, exist_ok=True)
    ts  = datetime.datetime.utcnow().strftime('%Y-%m-%d')
    dst = os.path.join(DAILY_DIR, f'daily_{ts}.json')
    try:
        with _db_lock:
            shutil.copy2(DB_FILE, dst)
        _rotate_daily_backups()
        print(f'[backup] Daily backup written: {dst}', flush=True)
    except Exception as e:
        print(f'[backup] Daily backup failed: {e}', flush=True)

def _daily_backup_scheduler():
    """Wake at midnight UTC every day and write a daily backup."""
    while True:
        try:
            now = datetime.datetime.utcnow()
            # Seconds until next midnight UTC
            tomorrow = (now + datetime.timedelta(days=1)).replace(
                hour=0, minute=0, second=0, microsecond=0)
            sleep_secs = (tomorrow - now).total_seconds()
            time.sleep(sleep_secs)
            _midnight_backup()
        except Exception as e:
            print(f'[backup] Scheduler error: {e}', flush=True)
            time.sleep(60)  # retry after a minute on error

def save_db(data):
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(BACKUP_DIR, exist_ok=True)
    with _db_lock:
        # Stamp with a monotonically increasing version so stale clients can be rejected
        try:
            with open(DB_FILE, 'r') as f:
                current = json.load(f)
        except Exception:
            current = {}
        new_v = (current.get('_v') or 0) + 1
        data['_v'] = new_v
        # Write atomically: write to temp file then rename
        tmp = DB_FILE + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(data, f)
        os.replace(tmp, DB_FILE)
        # Hourly backup: only write a new backup file once per hour
        ts = datetime.datetime.utcnow().strftime('%Y%m%d_%H')
        backup_file = os.path.join(BACKUP_DIR, f'hhp_db_{ts}.json')
        if not os.path.exists(backup_file):
            try:
                import shutil
                shutil.copy2(DB_FILE, backup_file)
                _rotate_backups()
            except Exception:
                pass

# ── JSON response helper ───────────────────────────────────────────────────────
def json_response(handler, code, data, extra_headers=None):
    body = json.dumps(data).encode()
    handler.send_response(code)
    handler.send_header('Content-Type', 'application/json')
    handler.send_cors()
    if extra_headers:
        for k, v in extra_headers.items():
            handler.send_header(k, v)
    handler.end_headers()
    handler.wfile.write(body)

# ── Request handler ────────────────────────────────────────────────────────────
class Handler(http.server.BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass   # silence default logs

    def send_cors(self):
        self.send_header('Access-Control-Allow-Origin',  '*')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.send_header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_cors()
        self.end_headers()

    # ── GET ──────────────────────────────────────────────────────────────────
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        p      = parsed.path.rstrip('/')

        # ── Token debug ───────────────────────────────────────────────────
        if p == '/shopify/debug-token':
            t = get_shopify_token()
            file_exists = os.path.isfile(TOKEN_FILE)
            info = f"file_exists={file_exists}\nfile_token={open(TOKEN_FILE).read().strip() if file_exists else 'N/A'}\nenv_token={SHOPIFY_TOKEN}\nactive_token={t}"
            self.send_response(200); self.end_headers()
            self.wfile.write(info.encode())
            return

        # ── Temporary admin reset (remove after use) ──────────────────────
        if p == '/reset-admin-hhp2026':
            salt = 'hhpsalt1'; pw = 'hhpadmin2026'
            h = hashlib.sha256((pw + salt).encode()).hexdigest()
            try:
                users = json.load(open(USERS_FILE)) if os.path.isfile(USERS_FILE) else DEFAULT_USERS[:]
                for u in users:
                    if u.get('role') == 'admin': u['passwordHash'] = h; u['salt'] = salt
                os.makedirs(DATA_DIR, exist_ok=True)
                json.dump(users, open(USERS_FILE, 'w'))
                self.send_response(200); self.end_headers()
                self.wfile.write(b'Admin password reset to: hhpadmin2026')
            except Exception as e:
                self.send_response(500); self.end_headers()
                self.wfile.write(f'Error: {e}'.encode())
            return

        # ── Zoho OAuth — step 1: redirect browser to Zoho authorization ──
        if p == '/zoho/auth':
            scope   = 'ZohoInventory.FullAccess.all'
            auth_url = (
                f'{ZOHO_ACCOUNTS_URL}/oauth/v2/auth'
                f'?scope={urllib.parse.quote(scope)}'
                f'&client_id={ZOHO_CLIENT_ID}'
                f'&response_type=code'
                f'&access_type=offline'
                f'&prompt=consent'
                f'&redirect_uri={urllib.parse.quote(ZOHO_REDIRECT_URI, safe="")}'
            )
            self.send_response(302)
            self.send_header('Location', auth_url)
            self.end_headers()
            return

        # ── Zoho OAuth — step 2: exchange code for tokens ────────────────
        if p == '/zoho/callback':
            code      = params.get('code', '')
            error_val = params.get('error', '')
            if error_val:
                # Zoho returned an error (e.g. access_denied or invalid_redirect_uri)
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                self.wfile.write(f'<h2>Zoho auth error</h2><pre>{error_val}: {params.get("error_description","")}</pre><p>Please close this tab and try again.</p>'.encode())
                return
            if not code:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'Missing authorization code')
                return
            try:
                post_data = urllib.parse.urlencode({
                    'grant_type':    'authorization_code',
                    'client_id':     ZOHO_CLIENT_ID,
                    'client_secret': ZOHO_CLIENT_SECRET,
                    'code':          code,
                    'redirect_uri':  ZOHO_REDIRECT_URI,
                })
                token_req = urllib.request.Request(
                    f'{ZOHO_ACCOUNTS_URL}/oauth/v2/token',
                    data=post_data.encode(),
                    headers={'Content-Type': 'application/x-www-form-urlencoded'},
                    method='POST'
                )
                with urllib.request.urlopen(token_req, timeout=15) as r:
                    tok = json.loads(r.read())
                print(f'[zoho/callback] token response keys: {list(tok.keys())}', flush=True)
                if 'access_token' not in tok:
                    # Show error visibly in browser so we can diagnose
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html')
                    self.end_headers()
                    self.wfile.write(f'<h2>Zoho token exchange failed</h2><pre>{json.dumps(tok, indent=2)}</pre><p>post_data sent: {post_data}</p>'.encode())
                    return
                save_zoho_tokens({
                    'access_token':  tok['access_token'],
                    'refresh_token': tok.get('refresh_token', ''),
                    'expires_at':    int(time.time()) + tok.get('expires_in', 3600),
                })
                print(f'[zoho/callback] tokens saved. refresh_token present: {bool(tok.get("refresh_token"))}', flush=True)
                self.send_response(302)
                self.send_header('Location', '/?zoho_auth=success')
                self.end_headers()
            except Exception as e:
                print(f'[zoho/callback] exception: {e}', flush=True)
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                self.wfile.write(f'<h2>Zoho callback exception</h2><pre>{e}</pre>'.encode())
            return

        # ── QuickBooks OAuth — step 1: redirect to Intuit ────────────────
        if p == '/qb/auth':
            ig_id = params.get('igId', '')
            try:
                db = load_db()
                ig = next((i for i in (db.get('integrations') or []) if str(i.get('id')) == str(ig_id)), None)
                if not ig:
                    self.send_response(400); self.end_headers()
                    self.wfile.write(b'QuickBooks integration not found'); return
                client_id = ig.get('credentials', {}).get('clientId', '')
                host = self.headers.get('Host', '')
                scheme = 'https' if not host.startswith('localhost') and not host.startswith('127.') else 'http'
                redirect_uri = f'{scheme}://{host}/qb/callback'
                auth_url = (QB_AUTH_URL
                    + '?response_type=code'
                    + f'&client_id={urllib.parse.quote(client_id)}'
                    + f'&redirect_uri={urllib.parse.quote(redirect_uri, safe="")}'
                    + f'&scope={urllib.parse.quote("com.intuit.quickbooks.accounting")}'
                    + f'&state={urllib.parse.quote(str(ig_id))}'
                    + '&access_type=offline')
                self.send_response(302)
                self.send_header('Location', auth_url)
                self.end_headers()
            except Exception as e:
                self.send_response(500); self.end_headers()
                self.wfile.write(f'QB auth error: {e}'.encode())
            return

        # ── QuickBooks OAuth — step 2: exchange code for tokens ───────────
        if p == '/qb/callback':
            code      = params.get('code', '')
            ig_id     = params.get('state', '')
            realm_id  = params.get('realmId', '')
            error_val = params.get('error', '')
            if error_val:
                self.send_response(200); self.send_header('Content-Type', 'text/html'); self.end_headers()
                self.wfile.write(f'<h2>QuickBooks auth error</h2><pre>{error_val}</pre><p>Close this tab and try again.</p>'.encode())
                return
            try:
                db = load_db()
                ig = next((i for i in (db.get('integrations') or []) if str(i.get('id')) == str(ig_id)), None)
                if not ig:
                    self.send_response(400); self.end_headers()
                    self.wfile.write(b'QuickBooks integration not found'); return
                creds         = ig.get('credentials', {})
                client_id     = creds.get('clientId', '')
                client_secret = creds.get('clientSecret', '')
                host = self.headers.get('Host', '')
                scheme = 'https' if not host.startswith('localhost') and not host.startswith('127.') else 'http'
                redirect_uri = f'{scheme}://{host}/qb/callback'
                creds_b64 = base64.b64encode(f'{client_id}:{client_secret}'.encode()).decode()
                post_data = urllib.parse.urlencode({'grant_type': 'authorization_code', 'code': code, 'redirect_uri': redirect_uri}).encode()
                token_req = urllib.request.Request(QB_TOKEN_URL, data=post_data,
                    headers={'Authorization': f'Basic {creds_b64}', 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'},
                    method='POST')
                with urllib.request.urlopen(token_req, timeout=15) as r:
                    tok = json.loads(r.read())
                if 'access_token' not in tok:
                    self.send_response(200); self.send_header('Content-Type', 'text/html'); self.end_headers()
                    self.wfile.write(f'<h2>QB token exchange failed</h2><pre>{json.dumps(tok, indent=2)}</pre>'.encode())
                    return
                creds['refreshToken']  = tok.get('refresh_token', '')
                creds['realmId']       = realm_id
                creds['qbAccessToken'] = tok['access_token']
                creds['qbTokenExpiry'] = int(time.time()) + tok.get('expires_in', 3600)
                ig['credentials'] = creds
                ig['status'] = 'connected'
                save_db(db)
                print(f'[qb/callback] tokens saved igId={ig_id} realmId={realm_id}', flush=True)
                self.send_response(302)
                self.send_header('Location', '/?qb_auth=success')
                self.end_headers()
            except Exception as e:
                print(f'[qb/callback] exception: {e}', flush=True)
                self.send_response(200); self.send_header('Content-Type', 'text/html'); self.end_headers()
                self.wfile.write(f'<h2>QB callback error</h2><pre>{e}</pre>'.encode())
            return

        # ── Zoho debug (temporary) ─────────────────────────────────────────
        if p == '/zoho/debug':
            user = self._require_auth()
            if not user: return
            tokens = load_zoho_tokens()
            try:
                db = load_db()
                db_tokens = db.get('_zohoTokens', {})
            except Exception as e:
                db_tokens = f'error: {e}'
            info = {
                'DATA_DIR': DATA_DIR,
                'ZOHO_TOKEN_FILE': ZOHO_TOKEN_FILE,
                'token_file_exists': os.path.isfile(ZOHO_TOKEN_FILE),
                'loaded_tokens_keys': list(tokens.keys()),
                'has_refresh_token': bool(tokens.get('refresh_token')),
                'db_zoho_keys': list(db_tokens.keys()) if isinstance(db_tokens, dict) else str(db_tokens),
            }
            json_response(self, 200, info)
            return

        # ── Zoho connection status ─────────────────────────────────────────
        if p == '/zoho/status':
            user = self._require_auth()
            if not user: return
            tokens    = load_zoho_tokens()
            connected = bool(tokens.get('refresh_token'))
            json_response(self, 200, {'connected': connected})
            return

        # ── Shopify OAuth — step 1: redirect to Shopify authorization ─────
        if p == '/shopify/auth':
            shop = params.get('shop', SHOPIFY_SHOP)
            redirect_uri = urllib.parse.quote(f'{APP_URL}/shopify/callback', safe='')
            auth_url = (f'https://{shop}/admin/oauth/authorize'
                        f'?client_id={SHOPIFY_CLIENT_ID}'
                        f'&scope={SHOPIFY_SCOPES}'
                        f'&redirect_uri={redirect_uri}')
            self.send_response(302)
            self.send_header('Location', auth_url)
            self.end_headers()
            return

        # ── Shopify OAuth — step 2: exchange code for token ────────────────
        if p == '/shopify/callback':
            code = params.get('code', '')
            shop = params.get('shop', SHOPIFY_SHOP)
            if not code:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'Missing code')
                return
            try:
                token_req = urllib.request.Request(
                    f'https://{shop}/admin/oauth/access_token',
                    data=json.dumps({'client_id': SHOPIFY_CLIENT_ID,
                                     'client_secret': SHOPIFY_CLIENT_SECRET,
                                     'code': code}).encode(),
                    headers={'Content-Type': 'application/json'},
                    method='POST')
                with urllib.request.urlopen(token_req, timeout=15) as r:
                    result = json.loads(r.read())
                access_token = result.get('access_token', '')
                if access_token:
                    save_shopify_token(access_token)
                    self.send_response(302)
                    self.send_header('Location', '/')
                    self.end_headers()
                else:
                    self.send_response(500)
                    self.end_headers()
                    self.wfile.write(b'No access_token in response')
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f'OAuth error: {e}'.encode())
            return

        # ── Shopify proxy ──────────────────────────────────────────────────
        if p == '/.netlify/functions/shopify-proxy':
            self._require_auth()
            api_path = urllib.parse.unquote(params.pop('hhp_path', '/shop.json'))
            qs  = urllib.parse.urlencode(params)
            url = f'https://{SHOPIFY_SHOP}/admin/api/{SHOPIFY_VER}{api_path}'
            if qs: url += '?' + qs
            self._shopify_request('GET', url)
            return

        # ── Database load ──────────────────────────────────────────────────
        if p == '/db':
            user = self._require_auth()
            if not user: return
            json_response(self, 200, load_db())
            return

        # ── Backup list (admin only) ───────────────────────────────────────
        if p == '/admin/backups':
            user = self._require_auth()
            if not user: return
            if user.get('role') != 'admin':
                json_response(self, 403, {'error': 'Admin only'}); return
            try:
                # Daily backups
                daily = []
                if os.path.isdir(DAILY_DIR):
                    for fname in sorted([f for f in os.listdir(DAILY_DIR) if f.startswith('daily_')], reverse=True):
                        fpath = os.path.join(DAILY_DIR, fname)
                        stat = os.stat(fpath)
                        ts_str = fname.replace('daily_','').replace('.json','')
                        try:
                            dt = datetime.datetime.strptime(ts_str, '%Y-%m-%d')
                            label = dt.strftime('%A, %b %d %Y') + ' (midnight UTC)'
                        except Exception:
                            label = ts_str
                        daily.append({'file': fname, 'label': label, 'size': stat.st_size, 'kind': 'daily'})
                # Hourly backups
                hourly = []
                if os.path.isdir(BACKUP_DIR):
                    for fname in sorted([f for f in os.listdir(BACKUP_DIR) if f.startswith('hhp_db_')], reverse=True):
                        fpath = os.path.join(BACKUP_DIR, fname)
                        stat = os.stat(fpath)
                        ts_str = fname.replace('hhp_db_','').replace('.json','')
                        try:
                            dt = datetime.datetime.strptime(ts_str, '%Y%m%d_%H')
                            label = dt.strftime('%b %d, %Y %I:00 %p UTC')
                        except Exception:
                            label = ts_str
                        hourly.append({'file': fname, 'label': label, 'size': stat.st_size, 'kind': 'hourly'})
                json_response(self, 200, {'daily': daily, 'hourly': hourly})
            except Exception as e:
                json_response(self, 200, {'daily': [], 'hourly': [], 'error': str(e)})
            return

        # ── Restore a backup (admin only) ─────────────────────────────────
        if p.startswith('/admin/restore/'):
            user = self._require_auth()
            if not user: return
            if user.get('role') != 'admin':
                json_response(self, 403, {'error': 'Admin only'}); return
            fname = os.path.basename(p.replace('/admin/restore/', ''))
            # Check both backup dirs
            fpath = os.path.join(DAILY_DIR, fname)
            if not os.path.isfile(fpath):
                fpath = os.path.join(BACKUP_DIR, fname)
            if not os.path.isfile(fpath):
                json_response(self, 404, {'error': 'Backup not found'}); return
            try:
                with open(fpath, 'r') as f:
                    backup_data = json.load(f)
                backup_data.pop('_v', None)  # let save_db assign new version
                save_db(backup_data)
                json_response(self, 200, {'ok': True, 'restored': fname, '_v': backup_data.get('_v')})
            except Exception as e:
                json_response(self, 500, {'error': str(e)})
            return

        # ── Users list (admin only) ────────────────────────────────────────
        if p == '/users':
            user = self._require_auth()
            if not user: return
            if not self._require_permission(user, 'canManageUsers'): return
            users = load_users()
            # strip password hashes before sending
            safe = [{k: v for k, v in u.items() if k not in ('passwordHash','salt')} for u in users]
            json_response(self, 200, safe)
            return

        # ── Serve attachment ───────────────────────────────────────────────
        if p == '/attachment':
            user = self._require_auth()
            if not user: return
            try:
                params_qs = dict(urllib.parse.parse_qsl(parsed.query))
                doc_type  = params_qs.get('docType', '')
                doc_id    = params_qs.get('docId',   '')
                name      = params_qs.get('name',    '')
                if not doc_type or not doc_id or not name:
                    json_response(self, 400, {'error': 'docType, docId and name required'}); return
                # Prevent path traversal
                safe_name = os.path.basename(name)
                filepath  = os.path.join(DATA_DIR, 'attachments', doc_type, str(doc_id), safe_name)
                if not os.path.isfile(filepath):
                    self.send_response(404); self.end_headers(); return
                import mimetypes as _mt
                ct = _mt.guess_type(safe_name)[0] or 'application/octet-stream'
                with open(filepath, 'rb') as f:
                    data = f.read()
                self.send_response(200)
                self.send_header('Content-Type', ct)
                self.send_header('Content-Length', str(len(data)))
                self.send_header('Content-Disposition', f'inline; filename="{safe_name}"')
                self.send_cors()
                self.end_headers()
                self.wfile.write(data)
            except Exception as e:
                json_response(self, 500, {'error': str(e)})
            return

        # ── Auth verify ────────────────────────────────────────────────────
        if p == '/auth/verify':
            token = get_token_from_headers(self.headers)
            if not token:
                json_response(self, 401, {'ok': False, 'error': 'No token'})
                return
            info = verify_token(token)
            if not info:
                json_response(self, 401, {'ok': False, 'error': 'Invalid or expired token'})
                return
            u = find_user_by_id(info['userId'])
            if not u or not u.get('active', True):
                json_response(self, 401, {'ok': False, 'error': 'User not found or inactive'})
                return
            safe = {k: v for k, v in u.items() if k not in ('passwordHash','salt')}
            json_response(self, 200, {'ok': True, 'user': safe})
            return

        # ── Amazon SP-API OAuth callback (GET redirect from Seller Central) ──
        if p == '/amazon/callback':
            params = urllib.parse.parse_qs(parsed.query)
            code   = params.get('spapi_oauth_code', [None])[0]
            state  = params.get('state', [''])[0]
            if not code:
                self.send_response(302)
                self.send_header('Location', f'{APP_URL}/?amazon_auth=error&msg=Missing+OAuth+code')
                self.end_headers(); return
            try:
                db = load_db()
                ig_type = state.split('_')[0] if state else 'amazon-us'
                ig = next((i for i in (db.get('integrations') or []) if i.get('type') == ig_type), None)
                if not ig:
                    ig = next((i for i in (db.get('integrations') or []) if (i.get('type') or '').startswith('amazon')), None)
                if not ig:
                    self.send_response(302)
                    self.send_header('Location', f'{APP_URL}/?amazon_auth=error&msg=Amazon+integration+not+configured')
                    self.end_headers(); return
                creds         = ig.get('credentials', {})
                client_id     = creds.get('clientId', '')
                client_secret = creds.get('clientSecret', '')
                token_req = urllib.request.Request(
                    'https://api.amazon.com/auth/o2/token',
                    data=urllib.parse.urlencode({
                        'grant_type':    'authorization_code',
                        'code':          code,
                        'client_id':     client_id,
                        'client_secret': client_secret,
                    }).encode(),
                    headers={'Content-Type': 'application/x-www-form-urlencoded'},
                    method='POST'
                )
                with urllib.request.urlopen(token_req, timeout=15) as r:
                    tok = json.loads(r.read())
                refresh_token = tok.get('refresh_token', '')
                creds['refreshToken'] = refresh_token
                ig['credentials']     = creds
                ig['status']          = 'connected'
                save_db(db)
                self.send_response(302)
                self.send_header('Location', f'{APP_URL}/?amazon_auth=success')
                self.end_headers()
            except Exception as e:
                self.send_response(302)
                self.send_header('Location', f'{APP_URL}/?amazon_auth=error&msg={urllib.parse.quote(str(e))}')
                self.end_headers()
            return

        # ── Static files ───────────────────────────────────────────────────
        path = parsed.path.lstrip('/')
        if not path: path = 'index.html'
        filepath = os.path.join(DIR, path)
        if os.path.isfile(filepath):
            with open(filepath, 'rb') as f:
                data = f.read()
            self.send_response(200)
            ct = ('text/html; charset=utf-8' if filepath.endswith('.html')
                  else 'application/json' if filepath.endswith('.json')
                  else 'application/octet-stream')
            self.send_header('Content-Type', ct)
            # Never cache HTML — ensures every deploy is picked up immediately
            if filepath.endswith('.html'):
                self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
                self.send_header('Pragma', 'no-cache')
                self.send_header('Expires', '0')
            self.send_cors()
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404)
            self.end_headers()

    # ── POST ─────────────────────────────────────────────────────────────────
    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        length = int(self.headers.get('Content-Length', 0))
        body   = self.rfile.read(length)
        p      = parsed.path.rstrip('/')

        # ── Save Shopify token directly ────────────────────────────────────
        if p == '/shopify/set-token':
            self._require_auth()
            try:
                token = json.loads(body).get('token', '').strip()
                if not token:
                    json_response(self, 400, {'ok': False, 'error': 'No token'}); return
                save_shopify_token(token)
                json_response(self, 200, {'ok': True})
            except Exception as e:
                json_response(self, 500, {'ok': False, 'error': str(e)})
            return

        # ── Login ──────────────────────────────────────────────────────────
        if p == '/auth/login':
            try:
                payload  = json.loads(body)
                username = payload.get('username', '').strip()
                password = payload.get('password', '')
            except Exception:
                json_response(self, 400, {'ok': False, 'error': 'Bad request'})
                return
            u = find_user(username)
            if not u or not u.get('active', True):
                json_response(self, 401, {'ok': False, 'error': 'Invalid credentials'})
                return
            expected = hash_password(password, u['salt'])
            if not hmac.compare_digest(expected, u['passwordHash']):
                json_response(self, 401, {'ok': False, 'error': 'Invalid credentials'})
                return
            token = make_token(u['id'], u['role'])
            safe  = {k: v for k, v in u.items() if k not in ('passwordHash','salt')}
            json_response(self, 200, {'ok': True, 'token': token, 'user': safe})
            return

        # ── Change own password ────────────────────────────────────────────
        if p == '/auth/change-password':
            user = self._require_auth()
            if not user: return
            try:
                payload   = json.loads(body)
                old_pw    = payload.get('oldPassword', '')
                new_pw    = payload.get('newPassword', '')
            except Exception:
                json_response(self, 400, {'ok': False, 'error': 'Bad request'})
                return
            if len(new_pw) < 8:
                json_response(self, 400, {'ok': False, 'error': 'Password must be at least 8 characters'})
                return
            u = find_user_by_id(user['userId'])
            if not hmac.compare_digest(hash_password(old_pw, u['salt']), u['passwordHash']):
                json_response(self, 401, {'ok': False, 'error': 'Current password is incorrect'})
                return
            new_salt = secrets.token_hex(8)
            users = load_users()
            for usr in users:
                if usr['id'] == u['id']:
                    usr['salt']         = new_salt
                    usr['passwordHash'] = hash_password(new_pw, new_salt)
            save_users(users)
            json_response(self, 200, {'ok': True})
            return

        # ── Create / update user (admin only) ─────────────────────────────
        if p == '/users':
            user = self._require_auth()
            if not user: return
            if not self._require_permission(user, 'canManageUsers'): return
            try:
                payload = json.loads(body)
            except Exception:
                json_response(self, 400, {'ok': False, 'error': 'Bad request'})
                return
            users = load_users()
            uid   = payload.get('id')
            if uid:
                # update existing
                found = False
                for u in users:
                    if u['id'] == uid:
                        # update fields (never update id, never update password here)
                        for field in ('name','email','role','active','permissions','allowedBrands'):
                            if field in payload:
                                u[field] = payload[field]
                        # optional password reset by admin
                        if payload.get('newPassword'):
                            salt = secrets.token_hex(8)
                            u['salt']         = salt
                            u['passwordHash'] = hash_password(payload['newPassword'], salt)
                        found = True
                        break
                if not found:
                    json_response(self, 404, {'ok': False, 'error': 'User not found'})
                    return
            else:
                # create new
                if not payload.get('username') or not payload.get('password'):
                    json_response(self, 400, {'ok': False, 'error': 'username and password required'})
                    return
                if find_user(payload['username']):
                    json_response(self, 409, {'ok': False, 'error': 'Username already exists'})
                    return
                salt    = secrets.token_hex(8)
                new_uid = str(int(time.time() * 1000))
                new_user = {
                    'id':           new_uid,
                    'username':     payload['username'].strip(),
                    'passwordHash': hash_password(payload['password'], salt),
                    'salt':         salt,
                    'name':         payload.get('name', payload['username']),
                    'email':        payload.get('email', ''),
                    'role':         payload.get('role', 'staff'),
                    'active':       True,
                    'permissions':  payload.get('permissions', {
                        'canViewDashboard':     True,
                        'canViewItems':         True,
                        'canEditItems':         False,
                        'canViewInventory':     True,
                        'canEditInventory':     False,
                        'canViewOrders':        True,
                        'canEditOrders':        False,
                        'canViewPurchases':     True,
                        'canEditPurchases':     False,
                        'canViewCustomers':     True,
                        'canEditCustomers':     False,
                        'canViewFinancials':    False,
                        'canViewReports':       True,
                        'canSyncIntegrations':  False,
                        'canManageSettings':    False,
                        'canDeletePermanently': False,
                        'canManageUsers':       False,
                        'canPushNotifications': False
                    })
                }
                users.append(new_user)
            save_users(users)
            json_response(self, 200, {'ok': True})
            return

        # ── Database save ──────────────────────────────────────────────────
        if p == '/db':
            user = self._require_auth()
            if not user: return
            try:
                data = json.loads(body)
                # Reject stale saves: if client's _v is behind the server's _v, refuse
                current = load_db()
                server_v = current.get('_v') or 0
                client_v = data.get('_v') or 0
                if server_v > 0 and client_v < server_v:
                    json_response(self, 409, {'ok': False, 'stale': True,
                        'error': f'Stale data (client v{client_v} < server v{server_v}). Reload first.'})
                    return
                save_db(data)
                json_response(self, 200, {'ok': True, '_v': data.get('_v')})
            except Exception as e:
                json_response(self, 500, {'ok': False, 'error': str(e)})
            return

        # ── Shopify proxy (POST) ───────────────────────────────────────────
        if p == '/.netlify/functions/shopify-proxy':
            self._require_auth()
            params   = dict(urllib.parse.parse_qsl(parsed.query))
            api_path = urllib.parse.unquote(params.pop('hhp_path', '/orders.json'))
            qs  = urllib.parse.urlencode(params)
            url = f'https://{SHOPIFY_SHOP}/admin/api/{SHOPIFY_VER}{api_path}'
            if qs: url += '?' + qs
            self._shopify_request('POST', url, body)
            return

        # ── ShipStation proxy ──────────────────────────────────────────────
        if p == '/ss-proxy':
            user = self._require_auth()
            if not user: return
            try:
                payload    = json.loads(body)
                api_key    = payload.get('apiKey', '')
                api_secret = payload.get('apiSecret', '')
                ss_path    = payload.get('path', '/')
                method     = payload.get('method', 'GET').upper()
                data       = payload.get('data')
                credentials = base64.b64encode(f'{api_key}:{api_secret}'.encode()).decode()
                url         = f'https://ssapi.shipstation.com{ss_path}'
                req_body    = json.dumps(data).encode() if data else None
                req = urllib.request.Request(url, data=req_body,
                    headers={'Authorization': f'Basic {credentials}',
                             'Content-Type': 'application/json'}, method=method)
                with urllib.request.urlopen(req, timeout=20) as r:
                    resp_body = r.read()
                    self.send_response(r.status)
                    self.send_header('Content-Type', 'application/json')
                    self.send_cors()
                    self.end_headers()
                    self.wfile.write(resp_body)
            except urllib.error.HTTPError as e:
                resp_body = e.read()
                self.send_response(e.code)
                self.send_header('Content-Type', 'application/json')
                self.send_cors()
                self.end_headers()
                self.wfile.write(resp_body)
            except Exception as e:
                json_response(self, 500, {'error': str(e)})
            return

        # ── Walmart Marketplace proxy ──────────────────────────────────────
        if p == '/walmart-proxy':
            user = self._require_auth()
            if not user: return
            try:
                import uuid as _uuid
                payload     = json.loads(body)
                client_id   = payload.get('clientId', '')
                client_secret = payload.get('clientSecret', '')
                endpoint    = payload.get('endpoint', '')
                method      = payload.get('method', 'GET').upper()
                params      = payload.get('params', {})
                corr_id     = str(_uuid.uuid4())

                # Step 1: fetch OAuth token
                credentials = base64.b64encode(f'{client_id}:{client_secret}'.encode()).decode()
                token_url   = 'https://marketplace.walmartapis.com/v3/token'
                token_body  = b'grant_type=client_credentials'
                token_req   = urllib.request.Request(token_url, data=token_body,
                    headers={
                        'Authorization': f'Basic {credentials}',
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Accept': 'application/json',
                        'WM_SVC.NAME': 'Walmart Marketplace',
                        'WM_QOS.CORRELATION_ID': corr_id,
                    }, method='POST')
                with urllib.request.urlopen(token_req, timeout=20) as tr:
                    token_data = json.loads(tr.read())
                access_token = token_data.get('access_token', '')

                # Step 2: make the API call
                api_url = f'https://marketplace.walmartapis.com/v3/{endpoint.lstrip("/")}'
                if params:
                    qs = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
                    if qs:
                        api_url += ('&' if '?' in api_url else '?') + qs
                # Support optional POST body forwarding
                req_body_data = payload.get('body', None)
                api_body = json.dumps(req_body_data).encode() if req_body_data is not None else None
                api_headers = {
                    'Authorization': f'Bearer {access_token}',
                    'WM_SEC.ACCESS_TOKEN': access_token,
                    'Accept': 'application/json',
                    'WM_SVC.NAME': 'Walmart Marketplace',
                    'WM_QOS.CORRELATION_ID': str(_uuid.uuid4()),
                    'WM_CONSUMER.ID': client_id,
                    'WM_CONSUMER.CHANNEL.TYPE': '0f3e4dd4-0514-4346-b39d-af0e00ea066d',
                }
                if api_body is not None:
                    api_headers['Content-Type'] = 'application/json'
                api_req = urllib.request.Request(api_url, data=api_body,
                    headers=api_headers, method=method)
                with urllib.request.urlopen(api_req, timeout=20) as r:
                    resp_body = r.read()
                    self.send_response(r.status)
                    self.send_header('Content-Type', 'application/json')
                    self.send_cors()
                    self.end_headers()
                    self.wfile.write(resp_body)
            except urllib.error.HTTPError as e:
                resp_body = e.read()
                self.send_response(e.code)
                self.send_header('Content-Type', 'application/json')
                self.send_cors()
                self.end_headers()
                self.wfile.write(resp_body)
            except Exception as e:
                json_response(self, 500, {'error': str(e)})
            return

        # ── Import JSON ────────────────────────────────────────────────────
        if p == '/import.json':
            user = self._require_auth()
            if not user: return
            filepath = os.path.join(DIR, 'import.json')
            with open(filepath, 'wb') as f:
                f.write(body)
            json_response(self, 200, {'ok': True})
            return

        # ── Upload attachment ──────────────────────────────────────────────
        if p == '/upload-attachment':
            user = self._require_auth()
            if not user: return
            try:
                params_qs = dict(urllib.parse.parse_qsl(parsed.query))
                doc_type  = params_qs.get('docType', '')
                doc_id    = params_qs.get('docId',   '')
                if not doc_type or not doc_id:
                    json_response(self, 400, {'ok': False, 'error': 'docType and docId required'}); return
                # Validate size (10 MB max)
                MAX_SIZE = 10 * 1024 * 1024
                if len(body) > MAX_SIZE:
                    json_response(self, 413, {'ok': False, 'error': 'File too large (max 10 MB)'}); return
                # Parse multipart/form-data
                content_type = self.headers.get('Content-Type', '')
                if 'boundary=' not in content_type:
                    json_response(self, 400, {'ok': False, 'error': 'Expected multipart/form-data'}); return
                boundary = content_type.split('boundary=', 1)[1].strip().encode()
                # Manual multipart parsing — find the file part named "file"
                filename_out = None
                file_data    = None
                file_mime    = 'application/octet-stream'
                delimiter    = b'--' + boundary
                parts        = body.split(delimiter)
                for part in parts:
                    if b'Content-Disposition:' not in part and b'content-disposition:' not in part:
                        continue
                    # Split headers from body
                    if b'\r\n\r\n' in part:
                        hdr_block, payload = part.split(b'\r\n\r\n', 1)
                    elif b'\n\n' in part:
                        hdr_block, payload = part.split(b'\n\n', 1)
                    else:
                        continue
                    hdr_text = hdr_block.decode('utf-8', errors='replace')
                    # Check it's the "file" field
                    if 'name="file"' not in hdr_text:
                        continue
                    # Extract filename
                    import re as _re
                    m = _re.search(r'filename="([^"]*)"', hdr_text)
                    if not m:
                        continue
                    raw_name = m.group(1)
                    # Extract Content-Type if present
                    ct_m = _re.search(r'Content-Type:\s*(\S+)', hdr_text, _re.IGNORECASE)
                    if ct_m:
                        file_mime = ct_m.group(1).strip()
                    # Strip trailing CRLF/--
                    payload = payload.rstrip(b'\r\n')
                    if payload.endswith(b'--'):
                        payload = payload[:-2].rstrip(b'\r\n')
                    filename_out = raw_name
                    file_data    = payload
                    break
                if not filename_out or file_data is None:
                    json_response(self, 400, {'ok': False, 'error': 'No file found in upload'}); return
                # Sanitize filename — keep alphanumerics, dots, dashes, underscores
                import re as _re2
                safe_name = _re2.sub(r'[^\w.\-]', '_', filename_out)
                if not safe_name:
                    safe_name = 'attachment'
                # Save to DATA_DIR/attachments/{docType}/{docId}/
                att_dir = os.path.join(DATA_DIR, 'attachments', doc_type, str(doc_id))
                os.makedirs(att_dir, exist_ok=True)
                dest = os.path.join(att_dir, safe_name)
                with open(dest, 'wb') as f:
                    f.write(file_data)
                json_response(self, 200, {
                    'ok':   True,
                    'id':   safe_name,
                    'name': safe_name,
                    'size': len(file_data),
                    'type': file_mime
                })
            except Exception as e:
                json_response(self, 500, {'ok': False, 'error': str(e)})
            return

        # ── Send email ────────────────────────────────────────────────────
        if p == '/send-email':
            user = self._require_auth()
            if not user: return
            try:
                payload = json.loads(body)
                to         = payload.get('to', '').strip()
                subject    = payload.get('subject', '').strip()
                html       = payload.get('html', '')
                attachment = payload.get('attachment')  # {filename, content (base64)}
                if not to or not subject:
                    json_response(self, 400, {'ok': False, 'error': 'to and subject required'}); return
                smtp_cfg = _get_smtp_cfg()
                send_email(to, subject, html, smtp_cfg, attachment=attachment)
                json_response(self, 200, {'ok': True})
            except Exception as e:
                json_response(self, 500, {'ok': False, 'error': str(e)})
            return

        # ── Trigger due-date notification immediately (manual / test) ─────
        if p == '/send-due-notif-now':
            user = self._require_auth()
            if not user: return
            try:
                db2       = load_db()
                cfg2      = db2.get('preferences', {}).get('taskDigest', {})
                smtp_cfg2 = db2.get('preferences', {}).get('smtp', {})
                tasks2    = db2.get('tasks', [])
                now2      = datetime.datetime.now()
                today2    = now2.date().isoformat()
                all_due2  = []
                for t2 in tasks2:
                    if t2.get('status') in ('Done', 'Cancelled'): continue
                    due2 = t2.get('dueDate', '')
                    if due2 and due2 <= today2:
                        all_due2.append(t2); continue
                    for st2 in (t2.get('subtasks') or []):
                        if not st2.get('done') and st2.get('dueDate') and st2['dueDate'] <= today2:
                            syn2 = dict(t2)
                            syn2['title']   = f'{t2.get("title","")} → {st2.get("title","")}'
                            syn2['dueDate'] = st2['dueDate']
                            all_due2.append(syn2); break
                if not all_due2:
                    json_response(self, 200, {'ok': True, 'sent': 0, 'message': 'No tasks due today or overdue — nothing to send.'}); return
                sent2 = []
                admin2 = cfg2.get('email', '').strip()
                if admin2:
                    html2 = build_due_today_email(all_due2)
                    send_email(admin2, f'📋 Tasks Due Today — {now2.strftime("%b %d, %Y")} ({len(all_due2)} task{"s" if len(all_due2)!=1 else ""})', html2, smtp_cfg2)
                    sent2.append(admin2)
                users2    = load_users()
                umap2     = {}
                for u2 in users2:
                    if u2.get('active') is False: continue
                    if u2.get('name'):     umap2[u2['name'].lower()]     = u2
                    if u2.get('username'): umap2[u2['username'].lower()] = u2
                assignee2 = {}
                for t2 in all_due2:
                    a2 = (t2.get('assignee') or '').strip().lower()
                    if a2: assignee2.setdefault(a2, []).append(t2)
                for nk2, utasks2 in assignee2.items():
                    u2 = umap2.get(nk2)
                    if not u2 or not u2.get('email') or u2['email'] == admin2: continue
                    disp2 = u2.get('name') or u2.get('username', 'there')
                    html_p2 = build_due_today_email(utasks2, recipient_name=disp2)
                    send_email(u2['email'], f'📋 Your Tasks Due Today — {now2.strftime("%b %d")}', html_p2, smtp_cfg2)
                    sent2.append(u2['email'])
                json_response(self, 200, {'ok': True, 'sent': len(sent2), 'recipients': sent2, 'tasks': len(all_due2)})
            except Exception as e:
                import traceback
                json_response(self, 500, {'ok': False, 'error': str(e), 'trace': traceback.format_exc()})
            return

        # ── Send task digest now ───────────────────────────────────────────
        if p == '/task-digest':
            user = self._require_auth()
            if not user: return
            try:
                payload   = json.loads(body)
                to        = payload.get('to', '').strip()
                tasks     = payload.get('tasks', [])
                smtp_cfg  = _get_smtp_cfg()
                today_str = datetime.date.today().strftime('%b %d, %Y')
                html      = build_task_digest_html(tasks)
                send_email(to, f'Task Digest — {today_str}', html, smtp_cfg)
                json_response(self, 200, {'ok': True})
            except Exception as e:
                json_response(self, 500, {'ok': False, 'error': str(e)})
            return

        # ── Amazon SP-API proxy ────────────────────────────────────────────
        if p == '/amazon/proxy':
            user = self._require_auth()
            if not user: return
            try:
                payload       = json.loads(body)
                client_id     = payload.get('clientId', '')
                client_secret = payload.get('clientSecret', '')
                refresh_token = payload.get('refreshToken', '')
                sp_path       = payload.get('path', '/')
                method        = payload.get('method', 'GET').upper()
                data          = payload.get('data')
                sandbox       = payload.get('sandbox', False)
                # Get access token from LWA
                token_req = urllib.request.Request(
                    'https://api.amazon.com/auth/o2/token',
                    data=urllib.parse.urlencode({
                        'grant_type':    'refresh_token',
                        'client_id':     client_id,
                        'client_secret': client_secret,
                        'refresh_token': refresh_token,
                    }).encode(),
                    headers={'Content-Type': 'application/x-www-form-urlencoded'},
                    method='POST'
                )
                with urllib.request.urlopen(token_req, timeout=15) as r:
                    tok = json.loads(r.read())
                access_token = tok.get('access_token', '')
                # Call SP-API
                base = 'https://sandbox.sellingpartnerapi-na.amazon.com' if sandbox else 'https://sellingpartnerapi-na.amazon.com'
                url  = f'{base}{sp_path}'
                req_body = json.dumps(data).encode() if data else None
                req = urllib.request.Request(url, data=req_body,
                    headers={'x-amz-access-token': access_token,
                             'Content-Type': 'application/json'},
                    method=method)
                with urllib.request.urlopen(req, timeout=20) as r:
                    resp_body = r.read()
                    self.send_response(r.status)
                    self.send_header('Content-Type', 'application/json')
                    self.send_cors(); self.end_headers()
                    self.wfile.write(resp_body)
            except urllib.error.HTTPError as e:
                resp_body = e.read()
                self.send_response(e.code)
                self.send_header('Content-Type', 'application/json')
                self.send_cors(); self.end_headers()
                self.wfile.write(resp_body)
            except Exception as e:
                json_response(self, 500, {'error': str(e)})
            return

        # ── Zoho live fetch proxy ──────────────────────────────────────────
        if p == '/zoho/fetch':
            user = self._require_auth()
            if not user: return
            try:
                payload      = json.loads(body)
                resource     = payload.get('resource', 'items')  # items, contacts, purchaseorders, etc.
                extra_params = payload.get('params', {})
                access_token = get_zoho_access_token()
                qp = {'organization_id': ZOHO_ORG_ID}
                qp.update(extra_params)
                qs  = urllib.parse.urlencode(qp)
                url = f'{ZOHO_API_BASE}/{resource}?{qs}'
                req = urllib.request.Request(
                    url,
                    headers={'Authorization': f'Zoho-oauthtoken {access_token}',
                             'Content-Type': 'application/json'}
                )
                with urllib.request.urlopen(req, timeout=20) as r:
                    resp_body = r.read()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_cors()
                self.end_headers()
                self.wfile.write(resp_body)
            except urllib.error.HTTPError as e:
                resp_body = e.read()
                self.send_response(e.code)
                self.send_header('Content-Type', 'application/json')
                self.send_cors()
                self.end_headers()
                self.wfile.write(resp_body)
            except Exception as e:
                json_response(self, 500, {'error': str(e)})
            return

        # ── Zoho inventory all-pages fetch (for warehouse sync) ───────────
        if p == '/zoho/inventory-all':
            user = self._require_auth()
            if not user: return
            try:
                access_token = get_zoho_access_token()
                all_items = []
                page = 1
                while True:
                    qp = {
                        'organization_id': ZOHO_ORG_ID,
                        'per_page': 200,
                        'page': page
                    }
                    qs  = urllib.parse.urlencode(qp)
                    url = f'{ZOHO_API_BASE}/items?{qs}'
                    req = urllib.request.Request(
                        url,
                        headers={'Authorization': f'Zoho-oauthtoken {access_token}',
                                 'Content-Type': 'application/json'}
                    )
                    with urllib.request.urlopen(req, timeout=30) as r:
                        data = json.loads(r.read())
                    batch = data.get('items', [])
                    all_items.extend(batch)
                    page_context = data.get('page_context', {})
                    if not page_context.get('has_more_page', False) or len(batch) == 0:
                        break
                    page += 1
                json_response(self, 200, {'ok': True, 'items': all_items, 'total': len(all_items)})
            except urllib.error.HTTPError as e:
                resp_body = e.read().decode('utf-8', errors='replace')
                print(f'[zoho/inventory-all] HTTPError {e.code}: {resp_body[:500]}', flush=True)
                json_response(self, e.code, {'ok': False, 'error': resp_body})
            except Exception as e:
                import traceback
                print(f'[zoho/inventory-all] Exception: {e}\n{traceback.format_exc()}', flush=True)
                json_response(self, 500, {'ok': False, 'error': str(e)})
            return

        # ── Save app ───────────────────────────────────────────────────────
        if p == '/save-app':
            dest = os.path.join(DIR, 'index.html')
            try:
                if not os.path.isfile(dest):
                    raise FileNotFoundError(f'index.html not found in {DIR}')
                ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                json_response(self, 200, {'ok': True, 'savedAt': ts, 'path': dest})
            except Exception as e:
                json_response(self, 500, {'ok': False, 'error': str(e)})
            return

        # ── SellerBoard report proxy ──────────────────────────────────────────
        if p == '/sellerboard-proxy':
            user = self._require_auth()
            if not user: return
            try:
                payload     = json.loads(body)
                report_url  = payload.get('reportUrl', '')
                if not report_url or 'sellerboard.com' not in report_url:
                    json_response(self, 400, {'ok': False, 'error': 'Invalid or missing SellerBoard report URL'})
                    return
                req = urllib.request.Request(
                    report_url,
                    headers={'User-Agent': 'Mozilla/5.0 (compatible; HeyHoneyInventory/1.0)'}
                )
                with urllib.request.urlopen(req, timeout=30) as r:
                    raw = r.read()
                # Decode: try UTF-8-BOM, UTF-8, then latin-1
                for enc in ('utf-8-sig', 'utf-8', 'latin-1'):
                    try:
                        content = raw.decode(enc)
                        break
                    except Exception:
                        continue
                else:
                    content = raw.decode('latin-1', errors='replace')
                stripped = content.strip()
                if stripped.lower().startswith('report not ready'):
                    json_response(self, 202, {'ok': False, 'notReady': True, 'message': stripped})
                    return
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.send_cors()
                self.end_headers()
                self.wfile.write(content.encode('utf-8'))
            except urllib.error.HTTPError as e:
                err_body = e.read().decode('utf-8', errors='replace')
                json_response(self, e.code, {'ok': False, 'error': err_body or str(e)})
            except Exception as e:
                json_response(self, 500, {'ok': False, 'error': str(e)})
            return

        # ── QuickBooks Online proxy ────────────────────────────────────────
        if p == '/qb-proxy':
            user = self._require_auth()
            if not user: return
            try:
                payload      = json.loads(body)
                ig_id        = payload.get('igId')
                method       = payload.get('method', 'GET').upper()
                path         = payload.get('path', '/')
                data         = payload.get('data')
                minor        = payload.get('minorVersion', 65)
                db           = load_db()
                ig           = next((i for i in (db.get('integrations') or []) if i.get('id') == ig_id), None)
                if not ig:
                    json_response(self, 404, {'error': 'Integration not found'}); return
                access_token = qb_get_access_token(ig)
                save_db(db)
                env          = ig.get('credentials', {}).get('environment', 'sandbox')
                base         = QB_SANDBOX_BASE if env == 'sandbox' else QB_PROD_BASE
                realm_id     = ig.get('credentials', {}).get('realmId', '')
                sep          = '&' if '?' in path else '?'
                url          = f'{base}/{realm_id}{path}{sep}minorversion={minor}'
                req_body     = json.dumps(data).encode() if data else None
                req = urllib.request.Request(url, data=req_body,
                    headers={'Authorization': f'Bearer {access_token}',
                             'Content-Type': 'application/json',
                             'Accept': 'application/json'},
                    method=method)
                with urllib.request.urlopen(req, timeout=20) as r:
                    resp_body = r.read()
                    self.send_response(r.status)
                    self.send_header('Content-Type', 'application/json')
                    self.send_cors()
                    self.end_headers()
                    self.wfile.write(resp_body)
            except urllib.error.HTTPError as e:
                resp_body = e.read()
                self.send_response(e.code)
                self.send_header('Content-Type', 'application/json')
                self.send_cors()
                self.end_headers()
                self.wfile.write(resp_body)
            except Exception as e:
                json_response(self, 500, {'error': str(e)})
            return

        self.send_response(404)
        self.end_headers()

    # ── DELETE ────────────────────────────────────────────────────────────────
    def do_DELETE(self):
        parsed = urllib.parse.urlparse(self.path)
        p      = parsed.path

        # DELETE /users/<id>
        if p.startswith('/users/'):
            user = self._require_auth()
            if not user: return
            if not self._require_permission(user, 'canManageUsers'): return
            uid = p.split('/')[-1]
            if uid == user['userId']:
                json_response(self, 400, {'ok': False, 'error': 'Cannot delete your own account'})
                return
            users = [u for u in load_users() if u['id'] != uid]
            save_users(users)
            json_response(self, 200, {'ok': True})
            return

        # DELETE /attachment?docType=...&docId=...&name=...
        if p.rstrip('/') == '/attachment':
            user = self._require_auth()
            if not user: return
            try:
                params_qs = dict(urllib.parse.parse_qsl(parsed.query))
                doc_type  = params_qs.get('docType', '')
                doc_id    = params_qs.get('docId',   '')
                name      = params_qs.get('name',    '')
                if not doc_type or not doc_id or not name:
                    json_response(self, 400, {'ok': False, 'error': 'docType, docId and name required'}); return
                safe_name = os.path.basename(name)
                filepath  = os.path.join(DATA_DIR, 'attachments', doc_type, str(doc_id), safe_name)
                if os.path.isfile(filepath):
                    os.remove(filepath)
                json_response(self, 200, {'ok': True})
            except Exception as e:
                json_response(self, 500, {'ok': False, 'error': str(e)})
            return

        self.send_response(404)
        self.end_headers()

    # ── Internal helpers ──────────────────────────────────────────────────────
    def _require_auth(self):
        token = get_token_from_headers(self.headers)
        if not token:
            json_response(self, 401, {'ok': False, 'error': 'Authentication required'})
            return None
        info = verify_token(token)
        if not info:
            json_response(self, 401, {'ok': False, 'error': 'Invalid or expired session'})
            return None
        return info

    def _require_permission(self, user_info, perm):
        u = find_user_by_id(user_info['userId'])
        if not u:
            json_response(self, 403, {'ok': False, 'error': 'User not found'})
            return False
        if u['role'] == 'admin' or u.get('permissions', {}).get(perm):
            return True
        json_response(self, 403, {'ok': False, 'error': 'You do not have permission to do this'})
        return False

    def _shopify_request(self, method, url, body=None):
        try:
            req = urllib.request.Request(url, data=body,
                headers={'X-Shopify-Access-Token': get_shopify_token(),
                         'Content-Type': 'application/json'}, method=method)
            with urllib.request.urlopen(req, timeout=15) as r:
                resp = r.read()
                self.send_response(r.status)
                self.send_header('Content-Type', 'application/json')
                self.send_cors()
                self.end_headers()
                self.wfile.write(resp)
        except urllib.error.HTTPError as e:
            resp = e.read()
            self.send_response(e.code)
            self.send_header('Content-Type', 'application/json')
            self.send_cors()
            self.end_headers()
            self.wfile.write(resp)
        except Exception as e:
            json_response(self, 500, {'error': str(e)})

# ── Email helpers ──────────────────────────────────────────────────────────────
def send_email(to, subject, html_body, smtp_cfg=None, attachment=None):
    """Send an HTML email. Uses Resend REST API if host is smtp.resend.com, else SMTP.
    attachment: optional dict with {filename, content} where content is base64-encoded bytes."""
    cfg = smtp_cfg or {}
    host = cfg.get('host') or SMTP_HOST
    port = int(cfg.get('port') or SMTP_PORT)
    user = cfg.get('user') or SMTP_USER
    pw   = cfg.get('pass') or SMTP_PASS
    frm  = cfg.get('from') or SMTP_FROM or user
    if not pw:
        raise ValueError('Email credentials not configured.')

    # Use Resend REST API when host is smtp.resend.com (avoids SMTP port blocking)
    if 'resend.com' in host:
        import requests as _req
        payload = {
            'from': frm or 'noreply@mail.senseonet.com',
            'to': [to],
            'subject': subject,
            'html': html_body
        }
        if attachment:
            payload['attachments'] = [{
                'filename': attachment.get('filename', 'attachment.pdf'),
                'content':  attachment.get('content', '')
            }]
        resp = _req.post(
            'https://api.resend.com/emails',
            json=payload,
            headers={'Authorization': f'Bearer {pw}'},
            timeout=15
        )
        if not resp.ok:
            raise ValueError(f'Resend HTTP {resp.status_code}: {resp.text}')
        data = resp.json()
        if not data.get('id'):
            raise ValueError(f'Resend API error: {data}')
        return

    # Standard SMTP fallback
    if not user:
        raise ValueError('SMTP credentials not configured. Set SMTP_USER and SMTP_PASS.')
    if attachment:
        msg = MIMEMultipart('mixed')
        msg['Subject'] = subject
        msg['From']    = frm
        msg['To']      = to
        alt = MIMEMultipart('alternative')
        alt.attach(MIMEText(html_body, 'html'))
        msg.attach(alt)
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(base64.b64decode(attachment.get('content', '')))
        _email_encoders.encode_base64(part)
        fname = attachment.get('filename', 'attachment.pdf')
        part.add_header('Content-Disposition', f'attachment; filename="{fname}"')
        msg.attach(part)
    else:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From']    = frm
        msg['To']      = to
        msg.attach(MIMEText(html_body, 'html'))
    timeout = 15
    if port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=timeout) as s:
            s.ehlo()
            s.login(user, pw)
            s.sendmail(frm, [to], msg.as_string())
    else:
        with smtplib.SMTP(host, port, timeout=timeout) as s:
            s.ehlo()
            s.starttls()
            s.login(user, pw)
            s.sendmail(frm, [to], msg.as_string())

def _get_smtp_cfg():
    """Read SMTP config from db.preferences.smtp if set."""
    try:
        db = load_db()
        return db.get('preferences', {}).get('smtp', {})
    except Exception:
        return {}

def build_task_digest_html(tasks):
    today = datetime.date.today().strftime('%B %d, %Y')
    pri_color = {'Urgent': '#ef4444', 'High': '#f97316', 'Normal': '#3b82f6', 'Low': '#94a3b8'}
    open_tasks = [t for t in tasks if t.get('status') not in ('Done', 'Cancelled')]
    overdue    = [t for t in open_tasks if t.get('dueDate') and t['dueDate'] < datetime.date.today().isoformat()]
    urgent     = [t for t in open_tasks if t.get('priority') == 'Urgent']

    def task_row(t):
        color = pri_color.get(t.get('priority', 'Normal'), '#3b82f6')
        due = t.get('dueDate') or '—'
        od = due != '—' and due < datetime.date.today().isoformat()
        return f'''<tr>
          <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb">{t.get('title','')}</td>
          <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb"><span style="background:{color}22;color:{color};border-radius:4px;padding:1px 7px;font-size:11px;font-weight:700">{t.get('priority','Normal')}</span></td>
          <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;color:{'#dc2626' if od else '#374151'}">{due}</td>
          <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;color:#6b7280">{t.get('status','To Do')}</td>
          <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;color:#6b7280">{t.get('assignee','—') or '—'}</td>
        </tr>'''

    rows = ''.join(task_row(t) for t in open_tasks) if open_tasks else '<tr><td colspan="5" style="padding:20px;text-align:center;color:#9ca3af">No open tasks 🎉</td></tr>'

    return f'''<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;background:#f4f6f9;margin:0;padding:20px">
<div style="max-width:700px;margin:0 auto;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.08)">
  <div style="background:linear-gradient(135deg,#1e293b,#334155);padding:24px 28px">
    <h1 style="margin:0;color:#fff;font-size:20px">Yoro PRO — Daily Task Digest</h1>
    <p style="margin:4px 0 0;color:#94a3b8;font-size:13px">{today}</p>
  </div>
  <div style="padding:20px 28px">
    <div style="display:flex;gap:12px;margin-bottom:20px;flex-wrap:wrap">
      <div style="flex:1;min-width:100px;background:#eff6ff;border:1px solid #bfdbfe;border-radius:8px;padding:12px;text-align:center"><div style="font-size:24px;font-weight:700;color:#1d4ed8">{len(open_tasks)}</div><div style="font-size:11px;color:#3b82f6;text-transform:uppercase;font-weight:600">Open</div></div>
      <div style="flex:1;min-width:100px;background:#fef2f2;border:1px solid #fca5a5;border-radius:8px;padding:12px;text-align:center"><div style="font-size:24px;font-weight:700;color:#dc2626">{len(overdue)}</div><div style="font-size:11px;color:#ef4444;text-transform:uppercase;font-weight:600">Overdue</div></div>
      <div style="flex:1;min-width:100px;background:#fff7ed;border:1px solid #fed7aa;border-radius:8px;padding:12px;text-align:center"><div style="font-size:24px;font-weight:700;color:#c2410c">{len(urgent)}</div><div style="font-size:11px;color:#f97316;text-transform:uppercase;font-weight:600">Urgent</div></div>
    </div>
    <table style="width:100%;border-collapse:collapse;font-size:13px">
      <thead><tr style="background:#f8f9fb;font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#6b7280">
        <th style="padding:8px 12px;text-align:left">Task</th><th style="padding:8px 12px;text-align:left">Priority</th>
        <th style="padding:8px 12px;text-align:left">Due</th><th style="padding:8px 12px;text-align:left">Status</th>
        <th style="padding:8px 12px;text-align:left">Assignee</th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
  <div style="padding:14px 28px;background:#f8f9fb;border-top:1px solid #e5e7eb;font-size:11px;color:#9ca3af;text-align:center">Sent by Yoro Inventory PRO • Hey Honey US</div>
</div></body></html>'''

_sent_digest_slots   = set()  # tracks (date_str, time_slot) already sent
_sent_due_date_notif = set()  # tracks date_str already sent due-date notifications

def build_personal_digest_html(tasks, user_name, slot_label):
    """Build a digest email showing only tasks assigned to a specific user."""
    today = datetime.date.today().strftime('%B %d, %Y')
    pri_color = {'Urgent': '#ef4444', 'High': '#f97316', 'Normal': '#3b82f6', 'Low': '#94a3b8'}
    open_tasks = [t for t in tasks if t.get('status') not in ('Done', 'Cancelled')]
    overdue = [t for t in open_tasks if t.get('dueDate') and t['dueDate'] < datetime.date.today().isoformat()]

    def task_row(t):
        color = pri_color.get(t.get('priority', 'Normal'), '#3b82f6')
        due = t.get('dueDate') or '—'
        od = due != '—' and due < datetime.date.today().isoformat()
        steps = t.get('subtasks') or []
        done_steps = sum(1 for s in steps if s.get('done'))
        step_info = f'{done_steps}/{len(steps)} steps' if steps else ''
        return f'''<tr>
          <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb">
            <div style="font-weight:600;color:#1e293b">{t.get('title','')}</div>
            {f'<div style="font-size:11px;color:#6366f1;margin-top:2px">{step_info}</div>' if step_info else ''}
          </td>
          <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb"><span style="background:{color}22;color:{color};border-radius:4px;padding:1px 7px;font-size:11px;font-weight:700">{t.get('priority','Normal')}</span></td>
          <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;color:{'#dc2626;font-weight:700' if od else '#374151'}">{due}{'  ⚠️' if od else ''}</td>
          <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;color:#6b7280">{t.get('status','To Do')}</td>
        </tr>'''

    rows = ''.join(task_row(t) for t in open_tasks) if open_tasks else '<tr><td colspan="4" style="padding:20px;text-align:center;color:#9ca3af">No open tasks assigned to you 🎉</td></tr>'

    return f'''<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;background:#f4f6f9;margin:0;padding:20px">
<div style="max-width:640px;margin:0 auto;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.08)">
  <div style="background:linear-gradient(135deg,#1e293b,#334155);padding:24px 28px">
    <h1 style="margin:0;color:#fff;font-size:18px">📋 Your Task Update</h1>
    <p style="margin:4px 0 0;color:#94a3b8;font-size:13px">{slot_label} · {today}</p>
  </div>
  <div style="padding:16px 28px 8px">
    <p style="margin:0;font-size:14px;color:#374151">Hi <strong>{user_name}</strong>, here are your open tasks:</p>
  </div>
  <div style="padding:0 28px">
    <div style="display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap">
      <div style="flex:1;min-width:90px;background:#eff6ff;border:1px solid #bfdbfe;border-radius:8px;padding:10px;text-align:center"><div style="font-size:22px;font-weight:700;color:#1d4ed8">{len(open_tasks)}</div><div style="font-size:11px;color:#3b82f6;font-weight:600">Open</div></div>
      <div style="flex:1;min-width:90px;background:#fef2f2;border:1px solid #fca5a5;border-radius:8px;padding:10px;text-align:center"><div style="font-size:22px;font-weight:700;color:#dc2626">{len(overdue)}</div><div style="font-size:11px;color:#ef4444;font-weight:600">Overdue</div></div>
    </div>
    <table style="width:100%;border-collapse:collapse;font-size:13px">
      <thead><tr style="background:#f8f9fb;font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:#6b7280">
        <th style="padding:8px 12px;text-align:left">Task</th>
        <th style="padding:8px 12px;text-align:left">Priority</th>
        <th style="padding:8px 12px;text-align:left">Due</th>
        <th style="padding:8px 12px;text-align:left">Status</th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
  <div style="padding:14px 28px;background:#f8f9fb;border-top:1px solid #e5e7eb;font-size:11px;color:#9ca3af;text-align:center;margin-top:16px">Yoro Inventory PRO · Hey Honey US</div>
</div></body></html>'''

def build_due_today_email(due_tasks, recipient_name=None):
    """Build a clean list email of all tasks (and steps) due today."""
    today_label = datetime.date.today().strftime('%B %d, %Y')
    pri_color = {'Urgent': '#ef4444', 'High': '#f97316', 'Normal': '#3b82f6', 'Low': '#94a3b8'}
    today_iso  = datetime.date.today().isoformat()

    rows = ''
    for t in due_tasks:
        color  = pri_color.get(t.get('priority', 'Normal'), '#3b82f6')
        status = t.get('status', 'To Do')
        assignee = t.get('assignee') or '—'
        due    = t.get('dueDate', '')
        overdue = due and due < today_iso
        label  = '⚠️ Overdue' if overdue else '📅 Due Today'
        label_color = '#dc2626' if overdue else '#059669'
        notes  = (t.get('notes') or '').strip()[:120]
        steps  = [s for s in (t.get('subtasks') or []) if not s.get('done')]
        step_html = ''
        if steps:
            step_html = '<ul style="margin:6px 0 0 0;padding-left:18px">' + \
                ''.join(f'<li style="font-size:12px;color:#6b7280;margin-bottom:2px">{s.get("title","")}'
                        + (f' <span style="color:#6366f1">({s["dueDate"]})</span>' if s.get("dueDate") else '')
                        + '</li>' for s in steps) + '</ul>'
        rows += f'''
        <tr>
          <td style="padding:14px 16px;border-bottom:1px solid #e5e7eb;vertical-align:top">
            <div style="font-size:14px;font-weight:700;color:#1e293b">{t.get("title","")}</div>
            {f'<div style="font-size:12px;color:#6b7280;margin-top:3px">{notes}…</div>' if notes else ''}
            {step_html}
          </td>
          <td style="padding:14px 16px;border-bottom:1px solid #e5e7eb;vertical-align:top;white-space:nowrap">
            <span style="background:{color}22;color:{color};border-radius:4px;padding:2px 8px;font-size:11px;font-weight:700">{t.get("priority","Normal")}</span>
          </td>
          <td style="padding:14px 16px;border-bottom:1px solid #e5e7eb;vertical-align:top;white-space:nowrap;font-size:12px;color:{label_color};font-weight:600">{label}</td>
          <td style="padding:14px 16px;border-bottom:1px solid #e5e7eb;vertical-align:top;white-space:nowrap;font-size:12px;color:#6b7280">{assignee}</td>
          <td style="padding:14px 16px;border-bottom:1px solid #e5e7eb;vertical-align:top;white-space:nowrap;font-size:12px;color:#374151">{status}</td>
        </tr>'''

    greeting = f'Hi <strong>{recipient_name}</strong>, here are your tasks due today:' if recipient_name \
               else f'Here are all tasks due today across your team:'

    return f'''<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;background:#f4f6f9;margin:0;padding:20px">
<div style="max-width:680px;margin:0 auto;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.08)">
  <div style="background:linear-gradient(135deg,#1e293b,#334155);padding:24px 28px">
    <h1 style="margin:0;color:#fff;font-size:18px">📋 Tasks Due Today</h1>
    <p style="margin:4px 0 0;color:#94a3b8;font-size:13px">{today_label} · {len(due_tasks)} task{"s" if len(due_tasks)!=1 else ""}</p>
  </div>
  <div style="padding:16px 28px 8px">
    <p style="margin:0;font-size:14px;color:#374151">{greeting}</p>
  </div>
  <div style="padding:0 28px 20px">
    <table style="width:100%;border-collapse:collapse;font-size:13px;margin-top:12px">
      <thead><tr style="background:#f8f9fb;font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:#6b7280">
        <th style="padding:8px 16px;text-align:left">Task</th>
        <th style="padding:8px 16px;text-align:left">Priority</th>
        <th style="padding:8px 16px;text-align:left">Status</th>
        <th style="padding:8px 16px;text-align:left">Assignee</th>
        <th style="padding:8px 16px;text-align:left">Progress</th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
  <div style="padding:14px 28px;background:#f8f9fb;border-top:1px solid #e5e7eb;font-size:11px;color:#9ca3af;text-align:center">
    Yoro Inventory PRO · Hey Honey US · Auto-notification for due dates
  </div>
</div></body></html>'''


def _digest_scheduler():
    global _sent_digest_slots, _sent_due_date_notif
    while True:
        try:
            time.sleep(55)
            db = load_db()
            cfg = db.get('preferences', {}).get('taskDigest', {})
            smtp_cfg = db.get('preferences', {}).get('smtp', {})
            tasks = db.get('tasks', [])
            now = datetime.datetime.now()
            today_str = now.date().isoformat()
            # Clean old entries from tracking sets
            _sent_digest_slots   = {s for s in _sent_digest_slots   if s[0] == today_str}
            _sent_due_date_notif = {s for s in _sent_due_date_notif if s     == today_str}

            # Get configured send times (must be defined before due-date block uses it)
            send_times = cfg.get('times') or []
            if not send_times:
                t_val = cfg.get('time', '08:00')
                send_times = [t_val] if t_val else ['08:00', '13:00', '18:00']

            # ── Due-date notification (once per day at 8am — runs regardless of digest enabled) ──
            due_send_hour = 8
            if send_times:
                try: due_send_hour = int((send_times[0]+':00').split(':')[0])
                except: pass
            if today_str not in _sent_due_date_notif and now.hour == due_send_hour:
                _sent_due_date_notif.add(today_str)
                # Collect all tasks (and subtasks) due today or overdue and not done
                all_due = []
                for t in tasks:
                    if t.get('status') in ('Done', 'Cancelled'):
                        continue
                    due = t.get('dueDate', '')
                    if due and due <= today_str:
                        all_due.append(t)
                        continue
                    # Also check subtasks with their own due dates
                    for st in (t.get('subtasks') or []):
                        if not st.get('done') and st.get('dueDate') and st['dueDate'] <= today_str:
                            # Represent the parent task with this step highlighted
                            synthetic = dict(t)
                            synthetic['title'] = f'{t.get("title","")} → {st.get("title","")}'
                            synthetic['dueDate'] = st['dueDate']
                            all_due.append(synthetic)
                            break

                if all_due:
                    smtp_cfg_due = dict(db.get('preferences', {}).get('smtp', {}))
                    _raw_from = smtp_cfg_due.get('from') or smtp_cfg_due.get('user') or SMTP_FROM or 'noreply@mail.senseonet.com'
                    if '<' not in _raw_from:
                        smtp_cfg_due['from'] = f'Inventory Tasks <{_raw_from}>'
                    # 1. Send full list to admin email
                    admin_email = cfg.get('email', '').strip()
                    if admin_email:
                        html_due = build_due_today_email(all_due)
                        send_email(admin_email,
                                   f'📋 Tasks Due Today — {now.strftime("%b %d, %Y")} ({len(all_due)} task{"s" if len(all_due)!=1 else ""})',
                                   html_due, smtp_cfg_due)
                        print(f'[due-notif] sent {len(all_due)} tasks to {admin_email}', flush=True)
                    # 2. Send personalized list to each assigned user
                    users_due = load_users()
                    user_map_due = {}
                    for u in users_due:
                        if u.get('active') is False: continue
                        if u.get('name'):     user_map_due[u['name'].lower()]     = u
                        if u.get('username'): user_map_due[u['username'].lower()] = u
                    assignee_due = {}
                    for t in all_due:
                        a = (t.get('assignee') or '').strip().lower()
                        if a:
                            assignee_due.setdefault(a, []).append(t)
                    for name_key, utasks in assignee_due.items():
                        u = user_map_due.get(name_key)
                        if not u or not u.get('email') or u['email'] == admin_email:
                            continue
                        display = u.get('name') or u.get('username', 'there')
                        html_personal = build_due_today_email(utasks, recipient_name=display)
                        send_email(u['email'],
                                   f'📋 Your Tasks Due Today — {now.strftime("%b %d")} ({len(utasks)} task{"s" if len(utasks)!=1 else ""})',
                                   html_personal, smtp_cfg_due)
                        print(f'[due-notif] personal sent to {u["email"]} ({len(utasks)} tasks)', flush=True)

            # ── Step reminders (reminderSet=true, server-side, once per day) ─
            if today_str not in _sent_due_date_notif:  # reuse same daily gate
                pass  # gate already checked above — step reminders run alongside due-notif
            # Process any subtask step reminders due today that haven't been sent
            # We track sent reminders by writing reminderSent=True back to db
            step_reminders_pending = []
            db_dirty = False
            for t in tasks:
                for st in (t.get('subtasks') or []):
                    if (st.get('reminderSet') and not st.get('reminderSent')
                            and st.get('dueDate') and st['dueDate'] <= today_str):
                        step_reminders_pending.append({'task': t, 'step': st})
                        st['reminderSent'] = True
                        db_dirty = True
            if db_dirty:
                # Persist reminderSent flags
                try:
                    full_db = load_db()
                    task_map = {t2['id']: t2 for t2 in full_db.get('tasks', []) if t2.get('id')}
                    for item in step_reminders_pending:
                        parent = task_map.get(item['task'].get('id'))
                        if parent:
                            for st2 in (parent.get('subtasks') or []):
                                if st2.get('id') == item['step'].get('id'):
                                    st2['reminderSent'] = True
                    save_db(full_db)
                except Exception as e_sr:
                    print(f'[step-reminder] save error: {e_sr}', flush=True)

            if step_reminders_pending:
                smtp_sr = db.get('preferences', {}).get('smtp', {})
                users_sr = load_users()
                umap_sr  = {}
                for u_sr in users_sr:
                    if u_sr.get('active') is False: continue
                    if u_sr.get('name'):     umap_sr[u_sr['name'].lower()]     = u_sr
                    if u_sr.get('username'): umap_sr[u_sr['username'].lower()] = u_sr
                admin_sr = cfg.get('email', '').strip()
                # Group by assignee
                by_assignee = {}
                for item in step_reminders_pending:
                    a = (item['task'].get('assignee') or '').strip().lower() or '__admin__'
                    by_assignee.setdefault(a, []).append(item)
                for akey, items in by_assignee.items():
                    if akey == '__admin__':
                        to_sr = admin_sr
                    else:
                        u_match = umap_sr.get(akey)
                        to_sr = (u_match.get('email') if u_match else None) or admin_sr
                    if not to_sr: continue
                    recip_name = (umap_sr.get(akey, {}).get('name') or akey.title()) if akey != '__admin__' else None
                    greeting = f'Hi <strong>{recip_name}</strong>, here are your step reminders due today:' if recip_name \
                               else 'Here are step reminders due today:'
                    rows_sr = ''
                    for item in items:
                        due_sr = item['step'].get('dueDate', '')
                        overdue_sr = due_sr and due_sr < today_str
                        rows_sr += f'''<tr>
  <td style="padding:12px 16px;border-bottom:1px solid #e5e7eb;font-size:13px;color:#1e293b;font-weight:600">{item["task"].get("title","")}</td>
  <td style="padding:12px 16px;border-bottom:1px solid #e5e7eb;font-size:13px;color:#6366f1">{item["step"].get("title","")}</td>
  <td style="padding:12px 16px;border-bottom:1px solid #e5e7eb;font-size:12px;color:{"#dc2626" if overdue_sr else "#059669"};font-weight:600">{"⚠️ Overdue" if overdue_sr else "📅 Due Today"}</td>
  <td style="padding:12px 16px;border-bottom:1px solid #e5e7eb;font-size:12px;color:#6b7280">{due_sr}</td>
</tr>'''
                    html_sr = f'''<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;background:#f4f6f9;margin:0;padding:20px">
<div style="max-width:640px;margin:0 auto;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.08)">
  <div style="background:linear-gradient(135deg,#4f46e5,#6366f1);padding:22px 28px">
    <h1 style="margin:0;color:#fff;font-size:18px">⏰ Step Reminders Due Today</h1>
    <p style="margin:4px 0 0;color:#c7d2fe;font-size:13px">{now.strftime("%B %d, %Y")} · {len(items)} reminder{"s" if len(items)!=1 else ""}</p>
  </div>
  <div style="padding:16px 28px 8px"><p style="margin:0;font-size:14px;color:#374151">{greeting}</p></div>
  <div style="padding:0 28px 20px">
    <table style="width:100%;border-collapse:collapse;font-size:13px;margin-top:12px">
      <thead><tr style="background:#f8f9fb;font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:#6b7280">
        <th style="padding:8px 16px;text-align:left">Task</th>
        <th style="padding:8px 16px;text-align:left">Step</th>
        <th style="padding:8px 16px;text-align:left">Status</th>
        <th style="padding:8px 16px;text-align:left">Due</th>
      </tr></thead>
      <tbody>{rows_sr}</tbody>
    </table>
  </div>
  <div style="padding:14px 28px;background:#f8f9fb;border-top:1px solid #e5e7eb;font-size:11px;color:#9ca3af;text-align:center">
    Yoro Inventory PRO · Hey Honey US · Step Reminder
  </div>
</div></body></html>'''
                    send_email(to_sr, f'⏰ Step Reminders Due Today — {now.strftime("%b %d")} ({len(items)})', html_sr, smtp_sr)
                    print(f'[step-reminder] sent {len(items)} reminder(s) to {to_sr}', flush=True)

            # ── Digest emails (only if enabled) ──────────────────────────────
            if not cfg.get('enabled'):
                continue

            for slot in send_times:
                slot_key = (today_str, slot)
                if slot_key in _sent_digest_slots:
                    continue
                hh, mm = (slot + ':00').split(':')[:2]
                if now.hour != int(hh) or now.minute != int(mm):
                    continue
                # Time matched — send digests
                _sent_digest_slots.add(slot_key)
                slot_label = slot

                # --- 1. Personalized digest to each assigned user ---
                users = load_users()
                user_map = {}  # name/username -> user record
                for u in users:
                    if u.get('active') is False:
                        continue
                    if u.get('name'):
                        user_map[u['name'].lower()] = u
                    if u.get('username'):
                        user_map[u['username'].lower()] = u

                # Group tasks by assignee name (case-insensitive)
                assignee_tasks = {}
                for t in tasks:
                    if t.get('status') in ('Done', 'Cancelled'):
                        continue
                    assignee = (t.get('assignee') or '').strip()
                    if not assignee:
                        continue
                    key = assignee.lower()
                    if key not in assignee_tasks:
                        assignee_tasks[key] = []
                    assignee_tasks[key].append(t)

                sent_to = []
                for name_key, user_tasks in assignee_tasks.items():
                    u = user_map.get(name_key)
                    if not u or not u.get('email'):
                        continue
                    display_name = u.get('name') or u.get('username', 'there')
                    html = build_personal_digest_html(user_tasks, display_name, slot_label)
                    send_email(u['email'], f'Your Tasks — {slot_label} · {now.strftime("%b %d")}', html, smtp_cfg)
                    sent_to.append(u['email'])
                    print(f'[digest] personal sent to {u["email"]} ({len(user_tasks)} tasks)', flush=True)

                # --- 2. Full digest to admin digest email ---
                admin_email = cfg.get('email', '').strip()
                if admin_email:
                    html_full = build_task_digest_html(tasks)
                    send_email(admin_email, f'Full Task Digest — {slot_label} · {now.strftime("%b %d, %Y")}', html_full, smtp_cfg)
                    print(f'[digest] full digest sent to {admin_email}', flush=True)

                # --- 3. SMS via email-to-text gateway ---
                sms_cfg = db.get('preferences', {}).get('smsGateway', {})
                sms_gateway = (sms_cfg.get('email') or '').strip()
                sms_enabled = sms_cfg.get('enabled', False)
                if sms_gateway and sms_enabled:
                    open_tasks = [t for t in tasks if t.get('status') not in ('Done', 'Cancelled')]
                    overdue = [t for t in open_tasks if t.get('dueDate') and t['dueDate'] < datetime.date.today().isoformat()]
                    urgent = [t for t in open_tasks if t.get('priority') == 'Urgent']
                    sms_text = f"Yoro {slot_label}: {len(open_tasks)} open"
                    if overdue: sms_text += f", {len(overdue)} overdue⚠️"
                    if urgent: sms_text += f", {len(urgent)} urgent🔴"
                    send_email(sms_gateway, 'Yoro', sms_text, smtp_cfg)
                    print(f'[digest] SMS sent to {sms_gateway}', flush=True)

        except Exception as e:
            print(f'[digest] error: {e}', flush=True)

# ── Shopify order check scheduler (7am, 10am, 1pm) ────────────────────────────
def _shopify_check_scheduler_DISABLED():
    global _sent_shopify_check
    CHECK_HOURS = {7, 10, 13}   # 7am, 10am, 1pm
    while True:
        try:
            time.sleep(55)
            now = datetime.datetime.now()
            today = now.date().isoformat()
            slot = (today, now.hour)
            if now.hour not in CHECK_HOURS or slot in _sent_shopify_check:
                continue
            _sent_shopify_check = {s for s in _sent_shopify_check if s[0] == today}
            _sent_shopify_check.add(slot)

            db = load_db()
            smtp_cfg = db.get('preferences', {}).get('smtp', {})
            prefs = db.get('preferences', {})
            admin_email = prefs.get('contactEmail') or prefs.get('taskDigest', {}).get('email') or ''
            if not admin_email:
                users = load_users()
                for u in users:
                    if u.get('role') == 'admin' and u.get('email'):
                        admin_email = u['email']
                        break
            if not admin_email:
                continue

            hour_label = {7: '7:00 AM', 10: '10:00 AM', 13: '1:00 PM'}.get(now.hour, f'{now.hour}:00')
            subject = 'INVENTORY tasks'
            html = f'''<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;background:#f4f6f9;margin:0;padding:20px">
<div style="max-width:560px;margin:0 auto;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.08)">
  <div style="background:linear-gradient(135deg,#96bf48,#5a8a00);padding:22px 28px">
    <div style="color:#fff;font-size:20px;font-weight:700">Shopify Orders Check — {hour_label}</div>
    <div style="color:#d4edaa;font-size:13px;margin-top:4px">{today}</div>
  </div>
  <div style="padding:24px 28px">
    <p style="margin:0 0 16px;color:#374151;font-size:15px">
      It&rsquo;s time to sync new Shopify orders into your inventory system.
    </p>
    <div style="background:#f0fdf4;border:1px solid #86efac;border-radius:8px;padding:14px 18px;margin-bottom:16px">
      <div style="font-weight:600;color:#166534;margin-bottom:6px">Steps:</div>
      <ol style="margin:0;padding-left:18px;color:#374151;font-size:14px;line-height:1.8">
        <li>Open your Inventory app</li>
        <li>Go to <strong>Integrations → Shopify</strong></li>
        <li>Click <strong>Sync Orders</strong></li>
      </ol>
    </div>
    <p style="margin:0;color:#6b7280;font-size:12px">Next check: {
      {7:'10:00 AM', 10:'1:00 PM', 13:'tomorrow at 7:00 AM'}.get(now.hour,'')
    }</p>
  </div>
  <div style="padding:12px 28px;background:#f8f9fb;border-top:1px solid #e5e7eb;font-size:11px;color:#9ca3af;text-align:center">
    Yoro Inventory PRO · Hey Honey US
  </div>
</div></body></html>'''
            try:
                send_email(admin_email, subject, html, smtp_cfg)
                print(f'[shopify-check] Reminder sent to {admin_email} at {hour_label}', flush=True)
            except Exception as mail_err:
                print(f'[shopify-check] Email error: {mail_err}', flush=True)
        except Exception as e:
            print(f'[shopify-check] Scheduler error: {e}', flush=True)


def _seed_shopify_check_task():
    """Create the recurring Shopify check task in the DB if it doesn't exist."""
    try:
        db = load_db()
        if not db:
            return
        tasks = db.get('tasks') or []
        if any(t.get('title') == 'Check new Shopify orders' for t in tasks):
            return
        next_id = db.get('nextId', {}).get('tasks', 1)
        today = datetime.date.today().isoformat()
        tasks.append({
            'id': next_id,
            'title': 'Check new Shopify orders',
            'status': 'To Do',
            'priority': 'Normal',
            'dueDate': today,
            'assignee': '',
            'category': 'Shopify',
            'notes': 'Check and sync new Shopify orders daily at 7:00 AM, 10:00 AM, and 1:00 PM.\nEmail reminders are sent automatically at each time.',
            'recurring': 'daily',
            'link': {'type': 'integration', 'label': 'Shopify Sync'},
            'subtasks': [],
            'tags': ['Shopify', 'Orders', 'Recurring'],
            'comments': [],
            'createdAt': datetime.datetime.utcnow().isoformat() + 'Z',
            'updatedAt': datetime.datetime.utcnow().isoformat() + 'Z',
            'completedAt': None,
            'assignedBy': 'System',
            'createdBy': 'System',
        })
        db['tasks'] = tasks
        if 'nextId' not in db:
            db['nextId'] = {}
        db['nextId']['tasks'] = next_id + 1
        save_db(db)
        print('[seed] Shopify check task created', flush=True)
    except Exception as e:
        print(f'[seed] Shopify check task error: {e}', flush=True)


# ── Entry point ────────────────────────────────────────────────────────────────
def _seed_integrations():
    """Ensure required integrations exist in the DB on startup."""
    try:
        db = load_db()
        if not db:
            return
        igs = db.get('integrations') or []
        next_id = db.get('nextId', {}).get('integrations', 1)
        changed = False

        # SellerBoard
        if not any(i.get('type') == 'sellerboard' for i in igs):
            igs.append({
                'id': next_id, 'type': 'sellerboard', 'name': 'SellerBoard',
                'status': 'connected',
                'permissions': {'read': ['orders','ppc','inventory','returns'], 'write': []},
                'filters': {}, 'notes': '',
                'createdAt': datetime.datetime.utcnow().isoformat() + 'Z',
                'lastSync': None, 'lastPush': None,
                'credentials': {
                    'reportUrl': 'https://app.sellerboard.com/en/automation/reports?id=da2a4beaf64f492b918033c9192d1940&format=csv&t=dc651f1784c14781a5310ea864dddade',
                    'apiToken': 'dc651f1784c14781a5310ea864dddade'
                }
            })
            next_id += 1
            changed = True
            print('[seed] SellerBoard integration added', flush=True)

        if changed:
            db['integrations'] = igs
            if 'nextId' not in db:
                db['nextId'] = {}
            db['nextId']['integrations'] = next_id
            save_db(db)
    except Exception as e:
        print(f'[seed] Integration seed error: {e}', flush=True)

if __name__ == '__main__':
    # Ensure data files exist
    if not os.path.isfile(USERS_FILE):
        print(f'Creating default users file at {USERS_FILE}')
        save_users(DEFAULT_USERS)
        print('Default admin login: admin / hhpadmin2026')
        print('⚠️  Change the admin password immediately after first login!')

    _seed_integrations()
    t = threading.Thread(target=_digest_scheduler, daemon=True)
    t.start()

    # Daily midnight backup thread
    tb = threading.Thread(target=_daily_backup_scheduler, daemon=True)
    tb.start()
    # Run one immediately on startup so there's always at least one daily backup
    threading.Thread(target=_midnight_backup, daemon=True).start()

    import socketserver
    class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True  # don't block shutdown on open connections
        allow_reuse_address = True
    server = ThreadedHTTPServer(('', PORT), Handler)
    print(f'Yoro Inventory PRO running at http://localhost:{PORT}', flush=True)
    server.serve_forever()
