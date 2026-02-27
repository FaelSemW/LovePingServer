import os
import sqlite3
import time
import secrets
from typing import Optional, Dict, Any

import requests
from fastapi import FastAPI, Request, Form, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext
from jose import jwt, JWTError

DB_PATH = os.getenv("DB_PATH", "loveping.db")

JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_ME__SET_JWT_SECRET")
JWT_ALG = "HS256"
JWT_TTL_SECONDS = int(os.getenv("JWT_TTL_SECONDS", "604800"))

SPOTIFY_CLIENT_ID = os.getenv("SPOTIFY_CLIENT_ID", "")
SPOTIFY_CLIENT_SECRET = os.getenv("SPOTIFY_CLIENT_SECRET", "")
SPOTIFY_REDIRECT_URI = os.getenv("SPOTIFY_REDIRECT_URI", "")
SPOTIFY_SCOPES = "user-read-currently-playing user-read-playback-state"

COOKIE_SECURE = os.getenv("COOKIE_SECURE", "true").lower() in ("1","true","yes","on")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="LovePing Server")
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "app", "templates"))
app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "app", "static")), name="static")

def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    cur = conn.cursor()
    cur.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        pass_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        spotify_refresh TEXT,
        spotify_linked_at INTEGER
    )
    ''')
    conn.commit()
    conn.close()

@app.on_event("startup")
def _startup():
    init_db()

def create_jwt(user_id: int, username: str) -> str:
    now = int(time.time())
    payload = {"sub": str(user_id), "u": username, "iat": now, "exp": now + JWT_TTL_SECONDS}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def read_jwt(token: str) -> Optional[Dict[str, Any]]:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except JWTError:
        return None

def get_user_by_username(username: str):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()
    return row

def get_user_by_id(uid: int):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id=?", (uid,))
    row = cur.fetchone()
    conn.close()
    return row

def current_user_web(request: Request):
    token = request.cookies.get("lp_token")
    if not token:
        return None
    data = read_jwt(token)
    if not data:
        return None
    return get_user_by_id(int(data["sub"]))

def require_user_web(request: Request):
    u = current_user_web(request)
    if not u:
        raise HTTPException(status_code=401, detail="not_logged_in")
    return u

def require_user_api(request: Request):
    auth = request.headers.get("authorization","")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing_bearer")
    token = auth.split(" ",1)[1].strip()
    data = read_jwt(token)
    if not data:
        raise HTTPException(status_code=401, detail="bad_token")
    u = get_user_by_id(int(data["sub"]))
    if not u:
        raise HTTPException(status_code=401, detail="no_user")
    return u

def spotify_authorize_url(state: str) -> str:
    from urllib.parse import urlencode
    if not SPOTIFY_CLIENT_ID or not SPOTIFY_REDIRECT_URI:
        raise HTTPException(status_code=500, detail="spotify_not_configured")
    q = urlencode({
        "client_id": SPOTIFY_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": SPOTIFY_REDIRECT_URI,
        "scope": SPOTIFY_SCOPES,
        "state": state,
        "show_dialog": "false",
    })
    return f"https://accounts.spotify.com/authorize?{q}"

def spotify_exchange_code(code: str) -> Dict[str, Any]:
    if not SPOTIFY_CLIENT_ID or not SPOTIFY_CLIENT_SECRET or not SPOTIFY_REDIRECT_URI:
        raise HTTPException(status_code=500, detail="spotify_not_configured")
    data = {"grant_type":"authorization_code","code":code,"redirect_uri":SPOTIFY_REDIRECT_URI}
    r = requests.post("https://accounts.spotify.com/api/token", data=data,
                      auth=(SPOTIFY_CLIENT_ID, SPOTIFY_CLIENT_SECRET), timeout=20)
    if r.status_code != 200:
        raise HTTPException(status_code=400, detail=f"spotify_token_error:{r.status_code}:{r.text}")
    return r.json()

def spotify_refresh(refresh_token: str) -> Dict[str, Any]:
    if not SPOTIFY_CLIENT_ID or not SPOTIFY_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="spotify_not_configured")
    data = {"grant_type":"refresh_token","refresh_token":refresh_token}
    r = requests.post("https://accounts.spotify.com/api/token", data=data,
                      auth=(SPOTIFY_CLIENT_ID, SPOTIFY_CLIENT_SECRET), timeout=20)
    if r.status_code != 200:
        raise HTTPException(status_code=400, detail=f"spotify_refresh_error:{r.status_code}:{r.text}")
    return r.json()

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    u = current_user_web(request)
    if u:
        return RedirectResponse("/dashboard", status_code=302)
    return templates.TemplateResponse("index.html", {"request": request, "user": None})

@app.get("/register", response_class=HTMLResponse)
def register_get(request: Request):
    return templates.TemplateResponse("register.html", {"request": request, "error": None, "user": None})

@app.post("/register")
def register_post(request: Request, username: str = Form(...), password: str = Form(...)):
    username = username.strip().lower()
    if len(username) < 3 or len(username) > 32:
        return templates.TemplateResponse("register.html", {"request": request, "error": "Usuário: 3 a 32 caracteres.", "user": None})
    if len(password) < 6:
        return templates.TemplateResponse("register.html", {"request": request, "error": "Senha: mínimo 6 caracteres.", "user": None})
    if get_user_by_username(username):
        return templates.TemplateResponse("register.html", {"request": request, "error": "Esse usuário já existe.", "user": None})

    ph = pwd_context.hash(password)
    conn = db()
    cur = conn.cursor()
    cur.execute("INSERT INTO users (username, pass_hash, created_at) VALUES (?,?,?)", (username, ph, int(time.time())))
    conn.commit()
    cur.execute("SELECT id FROM users WHERE username=?", (username,))
    uid = cur.fetchone()["id"]
    conn.close()

    token = create_jwt(uid, username)
    resp = RedirectResponse("/dashboard", status_code=302)
    resp.set_cookie("lp_token", token, httponly=True, samesite="lax", secure=COOKIE_SECURE)
    return resp

@app.get("/login", response_class=HTMLResponse)
def login_get(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None, "user": None})

@app.post("/login")
def login_post(request: Request, username: str = Form(...), password: str = Form(...)):
    username = username.strip().lower()
    u = get_user_by_username(username)
    if not u or not pwd_context.verify(password, u["pass_hash"]):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Usuário ou senha inválidos.", "user": None})
    token = create_jwt(u["id"], u["username"])
    resp = RedirectResponse("/dashboard", status_code=302)
    resp.set_cookie("lp_token", token, httponly=True, samesite="lax", secure=COOKIE_SECURE)
    return resp

@app.get("/logout")
def logout():
    resp = RedirectResponse("/", status_code=302)
    resp.delete_cookie("lp_token")
    resp.delete_cookie("lp_state")
    return resp

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, u=Depends(require_user_web)):
    domain = request.base_url._url.rstrip("/")
    ws_url = domain.replace("https://","wss://") + "/ws/love"
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": True,
        "username": u["username"],
        "linked": bool(u["spotify_refresh"]),
        "spotify_configured": bool(SPOTIFY_CLIENT_ID and SPOTIFY_CLIENT_SECRET and SPOTIFY_REDIRECT_URI),
        "redirect_uri": SPOTIFY_REDIRECT_URI or "(não configurado)",
        "domain": domain,
        "ws_url": ws_url,
    })

@app.get("/spotify/connect")
def spotify_connect(request: Request, u=Depends(require_user_web)):
    state = secrets.token_urlsafe(24)
    resp = RedirectResponse(spotify_authorize_url(state), status_code=302)
    resp.set_cookie("lp_state", state, httponly=True, samesite="lax", secure=COOKIE_SECURE)
    return resp

@app.get("/spotify/callback")
def spotify_callback(request: Request, code: Optional[str] = None, state: Optional[str] = None, error: Optional[str] = None, u=Depends(require_user_web)):
    if error:
        return RedirectResponse("/dashboard?spotify_error=1", status_code=302)
    if not code:
        raise HTTPException(status_code=400, detail="missing_code")
    expected = request.cookies.get("lp_state")
    if expected and state and expected != state:
        raise HTTPException(status_code=400, detail="bad_state")
    tok = spotify_exchange_code(code)
    refresh = tok.get("refresh_token")
    if not refresh:
        raise HTTPException(status_code=400, detail="no_refresh_token_returned")

    conn = db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET spotify_refresh=?, spotify_linked_at=? WHERE id=?",
                (refresh, int(time.time()), u["id"]))
    conn.commit()
    conn.close()

    resp = RedirectResponse("/dashboard?spotify_linked=1", status_code=302)
    resp.delete_cookie("lp_state")
    return resp

@app.post("/api/login")
def api_login(payload: Dict[str, Any]):
    username = (payload.get("username") or "").strip().lower()
    password = payload.get("password") or ""
    u = get_user_by_username(username)
    if not u or not pwd_context.verify(password, u["pass_hash"]):
        return JSONResponse({"error":"invalid_credentials"}, status_code=401)
    return {"token": create_jwt(u["id"], u["username"]), "username": u["username"], "spotify_linked": bool(u["spotify_refresh"])}

@app.post("/api/register")
def api_register(payload: Dict[str, Any]):
    username = (payload.get("username") or "").strip().lower()
    password = payload.get("password") or ""
    if len(username) < 3 or len(username) > 32 or len(password) < 6:
        return JSONResponse({"error":"invalid_input"}, status_code=400)
    if get_user_by_username(username):
        return JSONResponse({"error":"user_exists"}, status_code=409)
    ph = pwd_context.hash(password)
    conn = db()
    cur = conn.cursor()
    cur.execute("INSERT INTO users (username, pass_hash, created_at) VALUES (?,?,?)", (username, ph, int(time.time())))
    conn.commit()
    cur.execute("SELECT id FROM users WHERE username=?", (username,))
    uid = cur.fetchone()["id"]
    conn.close()
    return {"token": create_jwt(uid, username), "username": username}

@app.get("/api/spotify/currently-playing")
def api_currently(request: Request, u=Depends(require_user_api)):
    if not u["spotify_refresh"]:
        raise HTTPException(status_code=400, detail="spotify_not_linked")
    tok = spotify_refresh(u["spotify_refresh"])
    access = tok.get("access_token")
    if not access:
        raise HTTPException(status_code=400, detail="no_access_token")
    r = requests.get("https://api.spotify.com/v1/me/player/currently-playing",
                     headers={"Authorization": f"Bearer {access}"},
                     timeout=20)
    if r.status_code == 204:
        return {"is_playing": False, "item": None}
    if r.status_code != 200:
        raise HTTPException(status_code=400, detail=f"spotify_api_error:{r.status_code}:{r.text}")
    data = r.json()
    item = data.get("item") or {}
    return {
        "is_playing": bool(data.get("is_playing")),
        "track_id": item.get("id"),
        "name": item.get("name"),
    }

@app.get("/health")
def health():
    return {"ok": True}

rooms: Dict[str, set] = {}

@app.websocket("/ws/{room}")
async def ws_room(ws: WebSocket, room: str):
    await ws.accept()
    rooms.setdefault(room, set()).add(ws)
    try:
        while True:
            msg = await ws.receive_text()
            for client in list(rooms.get(room, set())):
                try:
                    await client.send_text(msg)
                except Exception:
                    pass
    except WebSocketDisconnect:
        pass
    finally:
        rooms.get(room, set()).discard(ws)
