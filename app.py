# ─────────────────────────────────────────────────────────────────────────────
# BuffTEKS Hub — GitHub-Centered Dashboard + Discord Notifications
# GitHub = source of truth | Discord = notifications | App = router + viewer
# ─────────────────────────────────────────────────────────────────────────────
from __future__ import annotations

import os, json, requests
from pathlib import Path
from flask import (
    Flask, render_template, redirect, url_for,
    session, request, abort, jsonify
)
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

# ─────────────────────────────────────────────────────────────────────────────
# App Setup
# ─────────────────────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent
load_dotenv(ROOT / ".env")

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.environ.get("APP_SECRET_KEY")

csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app)

# ─────────────────────────────────────────────────────────────────────────────
# Branding
# ─────────────────────────────────────────────────────────────────────────────
BRAND   = os.getenv("SITE_BRAND", "BuffTEKS")
TAGLINE = os.getenv("SITE_TAGLINE", "Student Engineers. Real Projects.")
ACCENT  = os.getenv("SITE_ACCENT", "#8a2be2")

# ─────────────────────────────────────────────────────────────────────────────
# Discord Config
# ─────────────────────────────────────────────────────────────────────────────
DISCORD_API        = "https://discord.com/api/v10"
DISCORD_GUILD_ID   = os.getenv("DISCORD_GUILD_ID")
DISCORD_BOT_TOKEN  = os.getenv("DISCORD_BOT_TOKEN")
DISCORD_CLIENT_ID  = os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
OAUTH_REDIRECT_URI = os.getenv("OAUTH_REDIRECT_URI")

# ─────────────────────────────────────────────────────────────────────────────
# GitHub Config
# ─────────────────────────────────────────────────────────────────────────────
REPO_EVENT_CHANNEL_MAP = json.loads(os.getenv("REPO_EVENT_CHANNEL_MAP", "{}"))

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def discord_headers():
    return {"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}

def user_is_in_guild(user_id: str) -> bool:
    r = requests.get(
        f"{DISCORD_API}/guilds/{DISCORD_GUILD_ID}/members/{user_id}",
        headers=discord_headers(),
        timeout=10,
    )
    return r.status_code == 200

def github_headers():
    return {
        "Accept": "application/vnd.github+json"
    }

def fetch_issues(repo: str):
    r = requests.get(
        f"https://api.github.com/repos/{repo}/issues",
        headers=github_headers(),
        params={"state": "open"},
        timeout=10,
    )
    if not r.ok:
        return []
    return [i for i in r.json() if "pull_request" not in i]

def fetch_prs(repo: str):
    r = requests.get(
        f"https://api.github.com/repos/{repo}/pulls",
        headers=github_headers(),
        timeout=10,
    )
    return r.json() if r.ok else []

def discord_webhook_send(webhook_url: str, content: str):
    if not webhook_url or not content:
        return
    try:
        requests.post(
            webhook_url,
            json={"content": content[:1900]},
            timeout=10,
        )
    except Exception as e:
        app.logger.warning(f"Discord webhook failed: {e}")

def format_github_event(event: str, p: dict) -> str:
    repo = p.get("repository", {}).get("full_name", "Unknown repo")

    if event == "push":
        pusher = p.get("pusher", {}).get("name", "someone")
        commits = p.get("commits", [])
        lines = "\n".join(
            f"- `{c.get('id','')[:7]}` {c.get('message','').strip()} — {c.get('author',{}).get('name','')}"
            for c in commits
        )
        return f"📦 **Push to `{repo}`** by **{pusher}**\n{lines or '(no commits)'}"

    if event == "issues":
        action = p.get("action")
        issue = p.get("issue", {})
        return (
            f"🐛 **Issue {action} — #{issue.get('number')}**\n"
            f"**{issue.get('title')}**\n{issue.get('html_url')}"
        )

    if event == "pull_request":
        action = p.get("action")
        pr = p.get("pull_request", {})
        return (
            f"🔀 **PR {action} — #{pr.get('number')}**\n"
            f"**{pr.get('title')}**\n{pr.get('html_url')}"
        )

    if event == "release":
        r = p.get("release", {})
        return (
            f"🚀 **New Release `{r.get('tag_name')}`**\n"
            f"**{r.get('name')}**\n{r.get('html_url')}"
        )

    return f"ℹ️ GitHub event `{event}` received for `{repo}`"

# ─────────────────────────────────────────────────────────────────────────────
# Template Globals
# ─────────────────────────────────────────────────────────────────────────────
@app.context_processor
def inject_globals():
    return dict(brand=BRAND, tagline=TAGLINE, accent=ACCENT)

# ─────────────────────────────────────────────────────────────────────────────
# Auth Gate
# ─────────────────────────────────────────────────────────────────────────────
SAFE_ENDPOINTS = {"discord_login", "discord_callback", "static", "favicon", "github_webhook"}

@app.before_request
def require_discord():
    ep = request.endpoint or ""
    if ep in SAFE_ENDPOINTS or ep.startswith("static"):
        return

    user = session.get("discord_user")
    if not user:
        return redirect(url_for("discord_login"))

    if not user_is_in_guild(user["id"]):
        abort(403)

@app.route("/favicon.ico")
def favicon():
    return ("", 204)

# ─────────────────────────────────────────────────────────────────────────────
# Discord OAuth
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/auth/discord/login")
def discord_login():
    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": OAUTH_REDIRECT_URI,
        "response_type": "code",
        "scope": "identify",
    }
    q = "&".join(f"{k}={requests.utils.quote(v)}" for k, v in params.items())
    return redirect(f"https://discord.com/oauth2/authorize?{q}")

@app.route("/auth/discord/callback")
def discord_callback():
    code = request.args.get("code")
    if not code:
        abort(400)

    tok = requests.post(
        f"{DISCORD_API}/oauth2/token",
        data={
            "client_id": DISCORD_CLIENT_ID,
            "client_secret": DISCORD_CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": OAUTH_REDIRECT_URI,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=10,
    ).json()

    user = requests.get(
        f"{DISCORD_API}/users/@me",
        headers={"Authorization": f"Bearer {tok['access_token']}"},
        timeout=10,
    ).json()

    session["discord_user"] = {
        "id": user["id"],
        "username": user.get("global_name") or user["username"],
    }

    return redirect(url_for("dashboard"))

@app.route("/auth/logout")
def logout():
    session.clear()
    return redirect(url_for("discord_login"))

# ─────────────────────────────────────────────────────────────────────────────
# Dashboard
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/")
def dashboard():
    data = {}
    for repo in REPO_EVENT_CHANNEL_MAP.keys():
        data[repo] = {
            "issues": fetch_issues(repo),
            "prs": fetch_prs(repo),
        }
    return render_template("dashboard.html", repos=data)

# ─────────────────────────────────────────────────────────────────────────────
# GitHub Webhook (Discord notifications)
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/webhooks/github")
@csrf.exempt
@limiter.exempt
def github_webhook():
    payload = request.get_json(silent=True) or {}
    event = request.headers.get("X-GitHub-Event")
    repo = payload.get("repository", {}).get("full_name")

    if not repo or not event:
        return jsonify({"ok": False}), 400

    repo_cfg = REPO_EVENT_CHANNEL_MAP.get(repo)
    if not repo_cfg:
        return jsonify({"ok": True})

    webhook = repo_cfg.get(event)
    if not webhook:
        return jsonify({"ok": True})

    message = format_github_event(event, payload)
    discord_webhook_send(webhook, message)

    return jsonify({"ok": True})

# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True)

