# ─────────────────────────────────────────────────────────────────────────────
# File: app.py
# BuffTEKS Hub — Discord OAuth + RBAC, tickets, and VIP join form
# Non-members are redirected to /join (VIP portal) after Discord login.
# ─────────────────────────────────────────────────────────────────────────────
from __future__ import annotations
import os, json, time, requests
from datetime import datetime
from pathlib import Path
from typing import Optional

from flask import (
    Flask, render_template, request, redirect, url_for, flash, session, jsonify, abort
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import case
from dotenv import load_dotenv

# ─────────────────────────────────────────────────────────────────────────────
# Env + App
# ─────────────────────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent
load_dotenv(ROOT / ".env")

app = Flask(
    __name__, static_folder="static", static_url_path="/static", template_folder="templates"
)
app.secret_key = os.environ.get("APP_SECRET_KEY", "dev")

# Branding
BRAND   = os.environ.get("SITE_BRAND", "BuffTEKS")
TAGLINE = os.environ.get("SITE_TAGLINE", "Student Engineers. Real Projects. Community Impact.")
ACCENT  = os.environ.get("SITE_ACCENT", "#8a2be2")

# Discord config
DISCORD_API           = "https://discord.com/api/v10"
DISCORD_GUILD_ID      = os.environ.get("DISCORD_GUILD_ID", "")
DISCORD_CHANNEL_ID    = os.environ.get("DISCORD_CHANNEL_ID", "")  # optional
DISCORD_BOT_TOKEN     = os.environ.get("DISCORD_BOT_TOKEN", "")   # for reads / role lookups
DISCORD_WEBHOOK_URL   = os.environ.get("DISCORD_WEBHOOK_URL", "") # for announcements
DISCORD_CLIENT_ID     = os.environ.get("DISCORD_CLIENT_ID", "")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET", "")
OAUTH_REDIRECT_URI    = os.environ.get("OAUTH_REDIRECT_URI", "http://localhost:5000/auth/discord/callback")

# Roles
ADMIN_ROLE_IDS   = {r.strip() for r in os.environ.get("ADMIN_ROLE_IDS", "").split(",") if r.strip()}
MEMBER_ROLE_IDS  = {r.strip() for r in os.environ.get("MEMBER_ROLE_IDS", "").split(",") if r.strip()}
ROLE_TTL_SECONDS = int(os.environ.get("ROLE_TTL_SECONDS", "600"))

# DB
os.makedirs(app.instance_path, exist_ok=True)
DEFAULT_SQLITE_PATH = (Path(app.instance_path) / 'buffteks.db').as_posix()
DB_URL = os.environ.get('DATABASE_URL', f'sqlite:///{DEFAULT_SQLITE_PATH}')
app.config["SQLALCHEMY_DATABASE_URI"] = DB_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# ─────────────────────────────────────────────────────────────────────────────
# Models
# ─────────────────────────────────────────────────────────────────────────────
class Ticket(db.Model):
    __tablename__ = "tickets"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)

    status = db.Column(db.String(20), default="submitted")    # submitted/triage/in_progress/awaiting_review/done + side
    priority = db.Column(db.String(20), default="normal")     # low, normal, high, urgent
    labels = db.Column(db.Text, default="[]")                 # JSON list[str]

    assignee_id = db.Column(db.String(40))      # Discord user id
    assignee_name = db.Column(db.String(120))   # cached display name
    created_by_id = db.Column(db.String(40))    # Discord user id
    created_by_name = db.Column(db.String(120))

    # helpers
    due_at = db.Column(db.DateTime)
    points = db.Column(db.Integer)
    checklist = db.Column(db.Text, default="[]")  # JSON [{text, checked}]
    blocked_reason = db.Column(db.Text)
    info_request = db.Column(db.Text)
    sprint = db.Column(db.String(50))
    watchers = db.Column(db.Text, default="[]")   # JSON list[str]

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    comments = db.relationship("TicketComment", backref="ticket", cascade="all, delete-orphan")

    def label_list(self) -> list[str]:
        try: return json.loads(self.labels or "[]")
        except Exception: return []

    def checklist_items(self) -> list[dict]:
        try: return json.loads(self.checklist or "[]")
        except Exception: return []

    def watcher_ids(self) -> list[str]:
        try: return json.loads(self.watchers or "[]")
        except Exception: return []

class TicketComment(db.Model):
    __tablename__ = "ticket_comments"
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("tickets.id", ondelete="CASCADE"), nullable=False)
    author_id = db.Column(db.String(40))
    author_name = db.Column(db.String(120))
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Attachment(db.Model):
    __tablename__ = "attachments"
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("tickets.id", ondelete="CASCADE"), nullable=False)
    filename = db.Column(db.String(255))
    url = db.Column(db.Text)
    kind = db.Column(db.String(30))
    uploaded_by_id = db.Column(db.String(40))
    uploaded_by_name = db.Column(db.String(120))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AuditEvent(db.Model):
    __tablename__ = "audit_events"
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("tickets.id", ondelete="CASCADE"), nullable=False)
    actor_id = db.Column(db.String(40))
    actor_name = db.Column(db.String(120))
    event_type = db.Column(db.String(40))  # created, updated, comment, assign, status
    payload = db.Column(db.Text, default="{}")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# VIP: Non-member intake form submissions
class NonMemberApplication(db.Model):
    __tablename__ = "nonmember_applications"
    id = db.Column(db.Integer, primary_key=True)
    discord_id = db.Column(db.String(40), nullable=False)
    discord_username = db.Column(db.String(120), nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    major = db.Column(db.String(120), nullable=False)
    student_email = db.Column(db.String(200), nullable=False)
    # NEW VIP fields
    commitment = db.Column(db.String(200))       # which team/project they will join
    commit_message = db.Column(db.String(200))   # fun commit line
    next_url = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ─────────────────────────────────────────────────────────────────────────────
# Lifecycle + permissions
# ─────────────────────────────────────────────────────────────────────────────
STATUS_FLOW = ["submitted", "triage", "in_progress", "awaiting_review", "done"]
SIDE_STATUSES = {"needs_more_info", "blocked", "cancelled"}
STATUS_CHOICES = set(STATUS_FLOW) | SIDE_STATUSES
PRIORITY_CHOICES = {"low", "normal", "high", "urgent"}

STATUS_TRANSITIONS = {
    ("submitted", "triage"): "admin",
    ("triage", "in_progress"): "admin",
    ("in_progress", "awaiting_review"): "assignee_or_admin",
    ("awaiting_review", "done"): "admin",
    ("awaiting_review", "needs_more_info"): "admin",
    ("needs_more_info", "in_progress"): "assignee_or_admin",
    ("in_progress", "blocked"): "assignee_or_admin",
    ("blocked", "in_progress"): "assignee_or_admin",
}

REQUIRED_FIELDS = {
    "awaiting_review": ["checklist"],
    "blocked": ["blocked_reason"],
    "needs_more_info": ["info_request"],
}

# ─────────────────────────────────────────────────────────────────────────────
# Helpers (Discord + RBAC)
# ─────────────────────────────────────────────────────────────────────────────
def discord_auth_headers():
    if not DISCORD_BOT_TOKEN:
        raise RuntimeError("Missing DISCORD_BOT_TOKEN")
    return {"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}

def user_is_in_guild(user_id: str) -> bool:
    if not user_id:
        return False
    url = f"{DISCORD_API}/guilds/{DISCORD_GUILD_ID}/members/{user_id}"
    r = requests.get(url, headers=discord_auth_headers(), timeout=10)
    return r.status_code == 200

def fetch_member_roles(discord_user_id: str) -> list[str]:
    if not discord_user_id:
        return []
    url = f"{DISCORD_API}/guilds/{DISCORD_GUILD_ID}/members/{discord_user_id}"
    r = requests.get(url, headers=discord_auth_headers(), timeout=10)
    if r.status_code != 200:
        return []
    return r.json().get("roles", []) or []

def compute_site_roles(discord_role_ids: set[str]) -> list[str]:
    site = set()
    if discord_role_ids & ADMIN_ROLE_IDS:
        site.add("admin")
    if discord_role_ids & MEMBER_ROLE_IDS or discord_role_ids:
        site.add("member")
    return [r for r in ["admin", "member"] if r in site]

def session_user() -> Optional[dict]:
    return session.get("discord_user")

def ensure_roles_fresh(force: bool = False):
    u = session_user()
    if not u:
        return
    now = int(time.time())
    if not force and now - u.get("roles_ts", 0) < ROLE_TTL_SECONDS and u.get("site_roles"):
        return
    roles = set(fetch_member_roles(u["id"]))
    u["site_roles"] = compute_site_roles(roles)
    u["roles_ts"] = now
    session["discord_user"] = u

def user_has_any(*required: str, force_refresh: bool = False) -> bool:
    u = session_user()
    if not u:
        return False
    ensure_roles_fresh(force=force_refresh)
    return bool(set(u.get("site_roles", [])).intersection(required))

def announce_to_discord(content: str) -> bool:
    if not DISCORD_WEBHOOK_URL:
        return False
    r = requests.post(DISCORD_WEBHOOK_URL, json={"content": content[:1900]}, timeout=10)
    return r.status_code in (200, 204)

def announce_ticket(event: str, t: Ticket, mention: bool = False, extra: str | None = None):
    link = url_for("ticket_detail", ticket_id=t.id, _external=True)
    parts = []
    if event == "created":
        parts.append(f"🆕 **Ticket #{t.id} — {t.title}** ({t.priority})")
    elif event == "updated":
        parts.append(f"✏️ **Updated Ticket #{t.id} — {t.title}**")
    elif event == "assigned":
        who = t.assignee_name or (t.assignee_id and f"<@{t.assignee_id}>") or "Unassigned"
        parts.append(f"🧭 **Assigned #{t.id} to {who}**")
    elif event == "status":
        parts.append(f"🔄 **Status: #{t.id} → `{t.status}`**")
    elif event == "comment":
        parts.append(f"💬 **Comment on #{t.id} — {t.title}**")
    if extra: parts.append(extra)
    if mention and t.assignee_id: parts.append(f"<@{t.assignee_id}>")
    parts.append(link)
    announce_to_discord("\n".join(parts))

# ─────────────────────────────────────────────────────────────────────────────
# Template globals
# ─────────────────────────────────────────────────────────────────────────────
@app.context_processor
def inject_globals():
    return dict(brand=BRAND, tagline=TAGLINE, accent=ACCENT)

# ─────────────────────────────────────────────────────────────────────────────
# Global gate — require sign-in; non-members → /join (VIP portal)
# ─────────────────────────────────────────────────────────────────────────────
SAFE_ENDPOINTS = {
    "discord_login",
    "discord_callback",
    "logout",
    "static",
    "join",
    "join_thanks",
    "favicon",
}

@app.before_request
def require_guild_membership():
    ep = (request.endpoint or "")
    if ep in SAFE_ENDPOINTS or ep.startswith("static"):
        return

    u = session_user()
    if not u:
        target = request.full_path if request.query_string else request.path
        return redirect(url_for("discord_login", next=target))

    ensure_roles_fresh()
    if not user_is_in_guild(u.get("id")):
        target = request.full_path if request.query_string else request.path
        return redirect(url_for("join", next=target))

# ─────────────────────────────────────────────────────────────────────────────
# Auth (Discord OAuth2)
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/auth/discord/login")
def discord_login():
    next_url = request.args.get("next") or request.referrer or url_for("tickets")
    session["post_login_redirect"] = next_url
    params = {
        "client_id": DISCORD_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": OAUTH_REDIRECT_URI,
        "scope": "identify",
        "prompt": "none",
    }
    q = "&".join([f"{k}={requests.utils.quote(v)}" for k, v in params.items() if v])
    return redirect(f"https://discord.com/oauth2/authorize?{q}")

@app.route("/auth/discord/callback")
def discord_callback():
    code = request.args.get("code")
    if not code:
        flash("No code from Discord.", "error")
        return redirect(url_for("tickets"))

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
    )
    if tok.status_code != 200:
        flash("Discord login failed.", "error")
        return redirect(url_for("tickets"))

    access_token = tok.json().get("access_token")
    u = requests.get(
        f"{DISCORD_API}/users/@me",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10,
    )
    if u.status_code != 200:
        flash("Discord login failed.", "error")
        return redirect(url_for("tickets"))

    user = u.json()
    session["discord_user"] = {
        "id": user["id"],
        "username": user.get("global_name") or user["username"],
    }

    if not user_is_in_guild(user["id"]):
        return redirect(url_for("join", next=session.get("post_login_redirect", url_for("tickets"))))

    role_ids = set(fetch_member_roles(user["id"]))
    session["discord_user"]["site_roles"] = compute_site_roles(role_ids)
    session["discord_user"]["roles_ts"] = int(time.time())
    return redirect(session.pop("post_login_redirect", url_for("tickets")))

@app.route("/auth/logout")
def logout():
    session.pop("discord_user", None)
    return redirect(url_for("tickets"))

# ─────────────────────────────────────────────────────────────────────────────
# VIP Join form
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/join", methods=["GET", "POST"])
def join():
    u = session_user()
    if not u:
        target = request.full_path if request.query_string else request.path
        return redirect(url_for("discord_login", next=target))

    # Already a member? let them through
    if user_is_in_guild(u.get("id")):
        return redirect(request.args.get("next") or url_for("tickets"))

    next_url = request.args.get("next") or session.get("post_login_redirect") or url_for("tickets")

    if request.method == "POST":
        first = (request.form.get("first_name") or "").strip()
        last  = (request.form.get("last_name") or "").strip()
        major = (request.form.get("major") or "").strip()
        email = (request.form.get("student_email") or "").strip()

        # Be lenient with the project/team field name to survive template drift
        def get_commitment(form):
            for k in ("commitment", "project_team", "project", "team"):
                v = (form.get(k) or "").strip()
                if v:
                    return v
            return ""
        commit_to = get_commitment(request.form)

        commit_msg = (request.form.get("commit_message") or "").strip()
        next_post  = (request.form.get("next") or next_url).strip()

        missing = [k for k,v in {
            "First name": first, "Last name": last, "Major": major,
            "Student email": email, "Project/team": commit_to
        }.items() if not v]

        if missing:
            flash("Please complete all required fields: " + ", ".join(missing), "error")
            return render_template("join_form.html",
                                   user=u, next_url=next_post, vip=True,
                                   first_name=first, last_name=last, major=major, student_email=email,
                                   commitment=commit_to, commit_message=commit_msg)

        app_row = NonMemberApplication(
            discord_id=u["id"], discord_username=u["username"],
            first_name=first, last_name=last, major=major, student_email=email,
            commitment=commit_to, commit_message=commit_msg, next_url=next_post
        )

        try:
            db.session.add(app_row)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            try:
                app_row.commitment = None
                app_row.commit_message = None
                db.session.add(app_row)
                db.session.commit()
                flash("Saved without VIP extras (run DB migration for commitment/commit_message).", "error")
            except Exception as e2:
                flash("Could not save your request. An admin has been notified.", "error")
                try:
                    announce_to_discord(f"⚠️ VIP form DB error for {u['username']} ({u['id']}): {e2}")
                except Exception:
                    pass
                return render_template("join_form.html",
                                       user=u, next_url=next_post, vip=True,
                                       first_name=first, last_name=last, major=major, student_email=email,
                                       commitment=commit_to, commit_message=commit_msg)

        try:
            announce_to_discord(
                "🧾 **New BuffTEKS VIP Access Request**\n"
                f"- Discord: {u['username']} (ID {u['id']})\n"
                f"- Name: {first} {last}\n"
                f"- Major: {major}\n"
                f"- Student Email: {email}\n"
                f"- Commitment: {commit_to or '(missing)'}\n"
                f"- Commit Msg: {commit_msg or '(none)'}"
            )
        except Exception:
            pass

        return redirect(url_for("join_thanks"))

    # GET
    return render_template("join_form.html", user=u, next_url=next_url, vip=True)




    # GET
    return render_template("join_form.html", user=u, next_url=next_url, vip=True)


@app.route("/join/thanks")
def join_thanks():
    return render_template("join_thanks.html")

# ─────────────────────────────────────────────────────────────────────────────
# Core pages
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/")
def home():
    return redirect(url_for("tickets"))

@app.route("/tickets")
def tickets():
    status = request.args.get("status")
    assignee = request.args.get("assignee")
    q = request.args.get("q", "").strip()

    qry = Ticket.query
    if status:
        qry = qry.filter(Ticket.status == status)
    if assignee:
        qry = qry.filter(Ticket.assignee_id == assignee)
    if q:
        like = f"%{q}%"
        qry = qry.filter((Ticket.title.ilike(like)) | (Ticket.description.ilike(like)))

    items = qry.order_by(
        case((Ticket.status == "open", 0),
             (Ticket.status == "in_progress", 1),
             (Ticket.status == "done", 2),
             else_=3),
        case((Ticket.priority == "urgent", 3),
             (Ticket.priority == "high", 2),
             (Ticket.priority == "normal", 1),
             else_=0).desc(),
        Ticket.updated_at.desc(),
    ).all()

    user = session_user()
    return render_template("tickets.html", tickets=items, user=user)

@app.route("/tickets/<int:ticket_id>")
def ticket_detail(ticket_id: int):
    t = Ticket.query.get_or_404(ticket_id)
    user = session_user()
    can_manage = bool(user) and user_has_any("admin", force_refresh=True)
    can_update_status = bool(user) and (
        user_has_any("admin", force_refresh=True) or (t.assignee_id and user.get("id") == t.assignee_id)
    )
    return render_template("ticket_detail.html", t=t, user=user, can_manage=can_manage, can_update_status=can_update_status)

# ─────────────────────────────────────────────────────────────────────────────
# Admin: create/update tickets
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/admin/tickets/new", methods=["GET", "POST"])
def admin_new_ticket():
    if not (session_user() and user_has_any("admin", force_refresh=True)):
        abort(403)
    if request.method == "POST":
        form = request.form
        title = form.get("title", "").strip()
        desc = form.get("description", "").strip()
        priority = form.get("priority", "normal").strip()
        labels = [s.strip() for s in (form.get("labels", "").split(",") if form.get("labels") else []) if s.strip()]
        assignee_id = form.get("assignee_id", "").strip() or None
        assignee_name = form.get("assignee_name", "").strip() or None
        if not title or not desc:
            flash("Title and description are required.", "error")
            return redirect(url_for("admin_new_ticket"))
        if priority not in PRIORITY_CHOICES:
            priority = "normal"

        u = session_user()
        t = Ticket(
            title=title, description=desc, priority=priority, labels=json.dumps(labels),
            assignee_id=assignee_id, assignee_name=assignee_name,
            created_by_id=u.get("id"), created_by_name=u.get("username"),
            status="submitted",
        )
        db.session.add(t); db.session.commit()
        db.session.add(AuditEvent(ticket_id=t.id, actor_id=u.get("id"), actor_name=u.get("username"),
                                  event_type="created", payload=json.dumps({"priority":priority,"labels":labels})))
        db.session.commit()
        announce_ticket("created", t, mention=bool(assignee_id))
        flash("Ticket created.", "ok")
        return redirect(url_for("ticket_detail", ticket_id=t.id))

    return render_template("admin_ticket_new.html")

@app.route("/admin/tickets/<int:ticket_id>/edit", methods=["GET", "POST"])
def admin_edit_ticket(ticket_id: int):
    if not (session_user() and user_has_any("admin", force_refresh=True)):
        abort(403)
    t = Ticket.query.get_or_404(ticket_id)
    if request.method == "POST":
        form = request.form
        old = {"status": t.status, "assignee_id": t.assignee_id, "priority": t.priority}
        t.title = form.get("title", t.title).strip()
        t.description = form.get("description", t.description).strip()
        pri = form.get("priority", t.priority).strip()
        t.priority = pri if pri in PRIORITY_CHOICES else t.priority
        st = form.get("status", t.status).strip()
        t.status = st if st in STATUS_CHOICES else t.status
        labels = [s.strip() for s in (form.get("labels", "").split(",") if form.get("labels") else []) if s.strip()]
        t.labels = json.dumps(labels)
        t.assignee_id = form.get("assignee_id", "").strip() or None
        t.assignee_name = form.get("assignee_name", "").strip() or None
        db.session.commit()

        u = session_user()
        db.session.add(AuditEvent(ticket_id=t.id, actor_id=u.get("id"), actor_name=u.get("username"),
                                  event_type="updated", payload=json.dumps({"old":old,"new":{"status":t.status,"priority":t.priority}})))
        db.session.commit()

        announce_ticket("updated", t)
        if old["assignee_id"] != t.assignee_id:
            announce_ticket("assigned", t, mention=True)
        if old["status"] != t.status:
            announce_ticket("status", t, mention=(t.status=="awaiting_review"))
        flash("Saved.", "ok")
        return redirect(url_for("ticket_detail", ticket_id=t.id))

    return render_template("admin_ticket_edit.html", t=t)

# ─────────────────────────────────────────────────────────────────────────────
# APIs: comments, status, assign
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/tickets/<int:ticket_id>/comment")
def api_comment(ticket_id: int):
    user = session_user()
    if not (user and user_is_in_guild(user.get("id"))):
        return jsonify({"ok": False, "error": "Not authorized"}), 401

    t = Ticket.query.get_or_404(ticket_id)
    data = request.get_json(silent=True) or {}
    body = (data.get("body") or "").strip()
    if not body:
        return jsonify({"ok": False, "error": "Empty comment"}), 400

    c = TicketComment(ticket_id=t.id, author_id=user.get("id"), author_name=user.get("username"), body=body)
    db.session.add(c)
    db.session.add(AuditEvent(ticket_id=t.id, actor_id=user.get("id"), actor_name=user.get("username"),
                              event_type="comment", payload=json.dumps({"length":len(body)})))
    db.session.commit()

    announce_ticket("comment", t)
    return jsonify({"ok": True, "comment": {
        "id": c.id,
        "author_name": c.author_name,
        "body": c.body,
        "created_at": c.created_at.isoformat(),
    }})

@app.post("/api/tickets/<int:ticket_id>/status")
def api_status(ticket_id: int):
    user = session_user()
    if not (user and user_is_in_guild(user.get("id"))):
        return jsonify({"ok": False, "error": "Not authorized"}), 401

    t = Ticket.query.get_or_404(ticket_id)
    data = request.get_json(silent=True) or {}
    new_status = (data.get("status") or "").strip()

    if new_status not in STATUS_CHOICES:
        return jsonify({"ok": False, "error": "Invalid status"}), 400

    old = t.status or "submitted"
    allowed = False
    role = STATUS_TRANSITIONS.get((old, new_status))
    is_admin = user_has_any("admin", force_refresh=True)
    is_assignee = t.assignee_id and user.get("id") == t.assignee_id

    if role == "admin" and is_admin:
        allowed = True
    elif role == "assignee_or_admin" and (is_admin or is_assignee):
        allowed = True
    elif old == new_status:
        allowed = True
    else:
        if is_admin:
            allowed = True

    if not allowed:
        return jsonify({"ok": False, "error": "Forbidden"}), 403

    t.status = new_status
    db.session.add(AuditEvent(ticket_id=t.id, actor_id=user.get("id"), actor_name=user.get("username"),
                              event_type="status", payload=json.dumps({"old":old,"new":new_status})))
    db.session.commit()

    announce_ticket("status", t, mention=(new_status=="awaiting_review"))
    return jsonify({"ok": True, "status": t.status})


@app.context_processor
def inject_globals():
    from datetime import timezone
    import math

    def reltime(dt):
        if not dt: return ""
        now = datetime.utcnow().replace(tzinfo=None)
        diff = (now - dt).total_seconds()
        past = diff >= 0
        s = abs(diff)
        for unit, secs in [("yr", 31536000), ("mo", 2592000), ("d", 86400), ("h", 3600), ("m", 60)]:
            if s >= secs:
                n = int(s // secs)
                return f"{n}{unit}{'' if n==1 else 's'} {'ago' if past else 'from now'}"
        return "just now"

    STATUS_COLORS = {
        "submitted": "bg-indigo-500/20 border-indigo-500/30 text-indigo-200",
        "triage": "bg-sky-500/20 border-sky-500/30 text-sky-200",
        "in_progress": "bg-amber-500/20 border-amber-500/30 text-amber-200",
        "awaiting_review": "bg-fuchsia-500/20 border-fuchsia-500/30 text-fuchsia-200",
        "done": "bg-emerald-500/20 border-emerald-500/30 text-emerald-200",
        "needs_more_info": "bg-pink-500/20 border-pink-500/30 text-pink-200",
        "blocked": "bg-red-500/20 border-red-500/30 text-red-200",
        "cancelled": "bg-slate-500/20 border-slate-500/30 text-slate-300",
        "open": "bg-indigo-500/20 border-indigo-500/30 text-indigo-200",
    }
    PRIORITY_COLORS = {
        "low": "bg-slate-500/20 border-slate-500/30 text-slate-200",
        "normal": "bg-zinc-500/20 border-zinc-500/30 text-zinc-200",
        "high": "bg-orange-500/20 border-orange-500/30 text-orange-200",
        "urgent": "bg-red-600/25 border-red-500/40 text-red-200",
    }

    def status_class(s): return STATUS_COLORS.get(s, "bg-white/10 border-white/20 text-white/80")
    def priority_class(p): return PRIORITY_COLORS.get(p, "bg-white/10 border-white/20 text-white/80")

    def checklist_progress(t):
        try:
            items = t.checklist_items()
            total = len(items)
            if not total: return (0, 0)
            done = sum(1 for i in items if i.get("checked"))
            return (done, total)
        except Exception:
            return (0, 0)

    def has_endpoint(name: str) -> bool:
        return name in app.view_functions

    return dict(
        brand=BRAND, tagline=TAGLINE, accent=ACCENT,
        reltime=reltime, status_class=status_class, priority_class=priority_class,
        checklist_progress=checklist_progress, has_endpoint=has_endpoint
    )



@app.context_processor
def inject_globals():
    def has_endpoint(name: str) -> bool:
        return name in app.view_functions
    return dict(
        brand=BRAND, tagline=TAGLINE, accent=ACCENT,
        has_endpoint=has_endpoint,  # <-- new
    )

@app.post("/api/tickets/<int:ticket_id>/assign")
def api_assign(ticket_id: int):
    u = session_user()
    if not (u and user_has_any("admin", force_refresh=True)):
        return jsonify({"ok": False, "error": "Admins only"}), 403

    t = Ticket.query.get_or_404(ticket_id)
    data = request.get_json(silent=True) or {}
    assignee_id = (data.get("assignee_id") or "").strip() or None
    assignee_name = (data.get("assignee_name") or "").strip() or None

    t.assignee_id = assignee_id
    t.assignee_name = assignee_name
    db.session.commit()

    link = url_for("ticket_detail", ticket_id=t.id, _external=True)
    mention = f" <@{assignee_id}>" if assignee_id else ""
    announce_to_discord(f"🧭 **Assignment: Ticket #{t.id} — {t.title}** → {assignee_name or assignee_id or 'Unassigned'}{mention}\n{link}")

    return jsonify({"ok": True, "assignee_id": t.assignee_id, "assignee_name": t.assignee_name})

# ─────────────────────────────────────────────────────────────────────────────
# Favicon + Bootstrap
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/favicon.ico")
def favicon():
    return ("", 204)

def init_db():
    with app.app_context():
        db.create_all()

# ─────────────────────────────────────────────────────────────────────────────
# Templates (written at import-time so Gunicorn has them)
# ─────────────────────────────────────────────────────────────────────────────
BASE_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{% block title %}{{ brand }} · Hub{% endblock %}</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    :root { --bt-accent: {{ accent }}; }
    .bg-bt { background: radial-gradient(1200px 600px at 20% -20%, rgba(138,43,226,0.25), transparent 60%); }
    .btn { @apply inline-flex items-center justify-center px-4 py-2 rounded-xl border border-white/20 hover:border-white/40 text-sm sm:text-[0.95rem]; }
    .btn-block { @apply w-full sm:w-auto; }
    .card { @apply rounded-2xl bg-white/5 border border-white/10; }
    .accent { color: var(--bt-accent); }
    .btn-accent { background: var(--bt-accent); color:#0a0a0a; @apply font-semibold rounded-xl px-4 py-2; }
    .tag { @apply text-xs px-2 py-0.5 rounded border border-white/20 bg-white/5; }
    @media (hover: hover) {.btn:hover { filter: brightness(1.05); }}
  </style>
</head>
<body class="bg-slate-950 text-white min-h-screen">
  {% set is_admin = (session.get('discord_user') and 'admin' in session.get('discord_user',{}).get('site_roles',[])) %}
  <header class="bg-bt border-b border-white/10">
    <div class="max-w-6xl mx-auto px-4 sm:px-6 py-4 sm:py-5">
      <div class="flex items-center justify-between">
        <a href="/" class="text-lg sm:text-xl font-extrabold tracking-tight">{{ brand }}</a>

        <!-- Desktop nav -->
        <nav class="hidden md:flex items-center gap-2 text-sm">
          <a href="{{ url_for('tickets') }}" class="btn">Tickets</a>
          {% if is_admin %}
            <a href="{{ url_for('admin_new_ticket') }}" class="btn">New Ticket</a>
            {% if 'admin_join_requests' in current_app.view_functions %}
              <a href="{{ url_for('admin_join_requests') }}" class="btn">VIP Requests</a>
            {% endif %}
          {% endif %}
          {% if session.get('discord_user') %}
            <span class="text-white/70 text-xs sm:text-sm">Signed in as <b>{{ session['discord_user']['username'] }}</b></span>
            <a class="btn" href="{{ url_for('logout') }}">Log out</a>
          {% else %}
            <a class="btn-accent" href="{{ url_for('discord_login') }}">Sign in with Discord</a>
          {% endif %}
        </nav>

        <!-- Mobile hamburger -->
        <button id="navToggle" class="md:hidden btn" aria-label="Open menu" aria-expanded="false">☰</button>
      </div>

      <!-- Mobile menu -->
      <nav id="mobileMenu" class="md:hidden hidden mt-3 grid gap-2">
        <a href="{{ url_for('tickets') }}" class="btn btn-block">Tickets</a>
        {% if is_admin %}
          <a href="{{ url_for('admin_new_ticket') }}" class="btn btn-block">New Ticket</a>
          {% if 'admin_join_requests' in current_app.view_functions %}
            <a href="{{ url_for('admin_join_requests') }}" class="btn btn-block">VIP Requests</a>
          {% endif %}
        {% endif %}
        {% if session.get('discord_user') %}
          <span class="text-white/70 text-sm">Signed in as <b>{{ session['discord_user']['username'] }}</b></span>
          <a class="btn btn-block" href="{{ url_for('logout') }}">Log out</a>
        {% else %}
          <a class="btn-accent btn-block" href="{{ url_for('discord_login') }}">Sign in with Discord</a>
        {% endif %}
      </nav>
    </div>
  </header>

  <main class="max-w-6xl mx-auto px-4 sm:px-6 py-6 sm:py-8">
    {% block content %}{% endblock %}
  </main>

  <script>
    const t = document.getElementById('navToggle');
    const m = document.getElementById('mobileMenu');
    t?.addEventListener('click', () => {
      const isOpen = !m.classList.contains('hidden');
      m.classList.toggle('hidden');
      t.setAttribute('aria-expanded', String(!isOpen));
    });
  </script>
</body>
</html>
"""


JOIN_FORM_HTML = r"""{% extends "base.html" %}
{% block title %}BuffTEKS VIP Server Access — {{ brand }}{% endblock %}
{% block content %}
<div class="max-w-xl mx-auto card p-6">
  <h1 class="text-2xl font-bold">BuffTEKS VIP Server Access</h1>
  <p class="text-white/70 mt-1">
    Hi <b>{{ user.username }}</b>! The <span class="font-semibold text-purple-400">BuffTEKS VIP Server</span> is our private collaboration space for active members.
  </p>
  <p class="mt-2 text-white/60 text-sm">
    To gain access, you’ll: <b>1)</b> join BuffTEKS, <b>2)</b> perform the
    <span class="font-semibold text-purple-400">Git Commit Ritual</span>, and <b>3)</b> commit to a project team.
  </p>

  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      <div class="mt-3 space-y-2">
        {% for cat,msg in messages %}
          <div class="rounded-lg px-3 py-2 text-sm {{ 'bg-red-500/20 border border-red-400/40' if cat=='error' else 'bg-white/10 border border-white/20' }}">{{ msg }}</div>
        {% endfor %}
      </div>
    {% endif %}
  {% endwith %}

  <form method="post" class="mt-4 grid gap-3">
    <input type="hidden" name="next" value="{{ next_url }}" />

    <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
      <div>
        <label class="text-xs text-white/60">First name</label>
        <input name="first_name" value="{{ first_name or '' }}" class="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-3 text-base" required />
      </div>
      <div>
        <label class="text-xs text-white/60">Last name</label>
        <input name="last_name" value="{{ last_name or '' }}" class="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-3 text-base" required />
      </div>
    </div>

    <div>
      <label class="text-xs text-white/60">Major</label>
      <input name="major" value="{{ major or '' }}" class="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-3 text-base" required />
    </div>

    <div>
      <label class="text-xs text-white/60">Student Email</label>
      <input type="email" inputmode="email" autocomplete="email" name="student_email" value="{{ student_email or '' }}" class="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-3 text-base" placeholder="you@buffs.wtamu.edu" required />
    </div>

    <div>
      <label class="text-xs text-white/60">Which BuffTEKS project/team are you joining?</label>
      <input name="commitment" value="{{ commitment or '' }}" class="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-3 text-base" placeholder="Web Dev, Outreach, AI Research, Infrastructure…" required />
    </div>

    <div>
      <label class="text-xs text-white/60">Describe your energy in a single commit message (optional)</label>
      <input name="commit_message" value="{{ commit_message or '' }}" class="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-3 text-base" placeholder='feat: ready to ship greatness 🚀' />
    </div>

    <button class="btn-accent btn-block mt-2">Request VIP Access</button>
  </form>

  <pre class="mt-4 text-xs text-white/40 bg-black/30 rounded-xl p-3 overflow-auto">
$ git add me
$ git commit -m "{{ commit_message or 'chore: joined BuffTEKS, ready to contribute' }}"
$ git push origin greatness
  </pre>
</div>
{% endblock %}
"""



JOIN_THANKS_HTML = r"""{% extends "base.html" %}
{% block title %}Thanks — {{ brand }}{% endblock %}
{% block content %}
<div class="max-w-xl mx-auto card p-6 text-center">
  <h1 class="text-2xl font-bold">Thanks!</h1>
  <p class="text-white/70 mt-1">Your VIP request has been submitted. A BuffTEKS officer will contact you soon.</p>
  <div class="mt-4">
    <a href="{{ url_for('tickets') }}" class="btn">Back to Home</a>
  </div>
</div>
{% endblock %}
"""


TICKETS_HTML = r"""{% extends "base.html" %}
{% block title %}Tickets — {{ brand }}{% endblock %}
{% block content %}
<h1 class="text-3xl font-bold">Tickets</h1>
<p class="text-white/60 text-sm">{{ tagline }}</p>

<form method="get" class="mt-4 flex flex-wrap items-end gap-3">
  <div>
    <label class="text-xs text-white/60">Status</label>
    <select name="status" class="block bg-black/40 border border-white/10 rounded-lg px-2 py-1.5">
      <option value="">Any</option>
      {% for s in ['open','in_progress','done','cancelled'] %}
        <option value="{{s}}" {{ 'selected' if request.args.get('status')==s else '' }}>{{s.replace('_',' ').title()}}</option>
      {% endfor %}
    </select>
  </div>
  <div>
    <label class="text-xs text-white/60">Assignee (Discord ID)</label>
    <input name="assignee" value="{{ request.args.get('assignee','') }}" class="bg-black/40 border border-white/10 rounded-lg px-2 py-1.5" placeholder="1234567890" />
  </div>
  <div class="flex-1 min-w-[200px]">
    <label class="text-xs text-white/60">Search</label>
    <input name="q" value="{{ request.args.get('q','') }}" class="w-full bg-black/40 border border-white/10 rounded-lg px-2 py-1.5" placeholder="title/description…" />
  </div>
  <button class="btn">Apply</button>
</form>

<div class="mt-6 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
  {% for t in tickets %}
  <a href="{{ url_for('ticket_detail', ticket_id=t.id) }}" class="card p-4 sm:p-5 block hover:border-white/20">
    <div class="flex items-start justify-between gap-3">
      <h3 class="font-semibold text-base sm:text-lg leading-snug">#{{t.id}} · {{ t.title }}</h3>
      <span class="tag whitespace-nowrap">{{ t.status.replace('_',' ').title() }}</span>
    </div>

    <!-- Line clamp fallback (3 lines) -->
    <p class="mt-2 text-white/80 text-sm sm:text-[0.95rem]" style="display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden;">
      {{ t.description }}
    </p>

    <div class="mt-3 flex flex-wrap items-center gap-2 text-xs text-white/60">
      <span class="tag">Priority: {{ t.priority }}</span>
      {% for label in t.label_list() %}<span class="tag">{{ label }}</span>{% endfor %}
    </div>

    {% if t.assignee_name or t.assignee_id %}
      <div class="mt-3 text-sm text-white/70">Assigned to: <b>{{ t.assignee_name or ('<@' ~ t.assignee_id ~ '>') }}</b></div>
    {% endif %}

    <div class="mt-2 text-xs text-white/50">Updated {{ t.updated_at.strftime('%Y-%m-%d %H:%M') }} UTC</div>
  </a>
  {% else %}
  <div class="text-white/60">No tickets found.</div>
  {% endfor %}
</div>
{% endblock %}
"""



TICKET_DETAIL_HTML = r"""{% extends "base.html" %}
{% block title %}#{{ t.id }} — {{ t.title }} · {{ brand }}{% endblock %}
{% block content %}
<div class="grid lg:grid-cols-3 gap-6">
  <section class="lg:col-span-2 card p-5">
    <header class="flex items-start justify-between gap-3">
      <div>
        <h1 class="text-2xl font-bold">#{{ t.id }} · {{ t.title }}</h1>
        <div class="mt-1 flex flex-wrap items-center gap-2 text-xs text-white/60">
          <span class="tag">{{ t.status.replace('_',' ').title() }}</span>
          <span class="tag">Priority: {{ t.priority }}</span>
          {% for label in t.label_list() %}<span class="tag">{{ label }}</span>{% endfor %}
        </div>
      </div>
      {% if can_manage %}
        <a class="btn" href="{{ url_for('admin_edit_ticket', ticket_id=t.id) }}">Edit</a>
      {% endif %}
    </header>

    <article class="prose prose-invert max-w-none mt-4">
      <p class="whitespace-pre-wrap">{{ t.description }}</p>
    </article>

    <hr class="my-5 border-white/10" />

    <h2 class="font-semibold">Comments</h2>
    <div id="comments" class="mt-3 space-y-3">
      {% for c in t.comments %}
      <div class="card p-3">
        <div class="text-sm"><b>{{ c.author_name }}</b> <span class="text-white/50">· {{ c.created_at.strftime('%Y-%m-%d %H:%M') }} UTC</span></div>
        <div class="mt-1 whitespace-pre-wrap">{{ c.body }}</div>
      </div>
      {% else %}
      <div class="text-white/60">No comments yet.</div>
      {% endfor %}
    </div>

    {% if user %}
    <div class="mt-4">
      <textarea id="commentBox" rows="4" class="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2 text-sm sm:text-base" placeholder="Write a comment…"></textarea>
      <div class="mt-2 flex justify-end"><button id="commentBtn" class="btn-accent btn-block sm:btn">Post Comment</button></div>
    </div>
    {% endif %}
  </section>

  <aside class="card p-5">
    <h3 class="font-semibold">Assignee</h3>
    <p class="mt-1 text-white/80">{{ t.assignee_name or (t.assignee_id and ('<@' ~ t.assignee_id ~ '>')) or 'Unassigned' }}</p>

    {% if can_manage %}
    <div class="mt-3">
      <label class="text-xs text-white/60">Discord ID</label>
      <input id="assigneeId" value="{{ t.assignee_id or '' }}" class="w-full bg-black/40 border border-white/10 rounded-lg px-2 py-1.5" />
      <label class="text-xs text-white/60 mt-2 block">Display Name</label>
      <input id="assigneeName" value="{{ t.assignee_name or '' }}" class="w-full bg-black/40 border border-white/10 rounded-lg px-2 py-1.5" />
      <button id="assignBtn" class="btn-accent mt-2 w-full sm:w-auto">Assign</button>
    </div>
    {% endif %}

    <h3 class="font-semibold mt-6">Status</h3>
    <div class="mt-2 grid grid-cols-2 sm:grid-cols-4 gap-2">
      {% for s in ['open','in_progress','done','cancelled'] %}
        <button class="btn {% if t.status==s %}border-white/60{% endif %} btn-block" data-status="{{s}}" {% if not can_update_status %}disabled{% endif %}>
          {{ s.replace('_',' ').title() }}
        </button>
      {% endfor %}
    </div>

    <div class="text-xs text-white/50 mt-6">
      <div>Created: {{ t.created_at.strftime('%Y-%m-%d %H:%M') }} UTC</div>
      <div>Updated: {{ t.updated_at.strftime('%Y-%m-%d %H:%M') }} UTC</div>
      <div>By: {{ t.created_by_name or t.created_by_id }}</div>
    </div>
  </aside>
</div>

<script>
const ticketId = {{ t.id }};
const commentBtn = document.getElementById('commentBtn');
const commentBox = document.getElementById('commentBox');
const comments = document.getElementById('comments');
const assignBtn = document.getElementById('assignBtn');
const assigneeId = document.getElementById('assigneeId');
const assigneeName = document.getElementById('assigneeName');

function esc(s){return (s||'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');}

commentBtn?.addEventListener('click', async () => {
  const body = commentBox.value.trim();
  if(!body) return;
  const r = await fetch(`/api/tickets/${ticketId}/comment`, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({body})});
  const data = await r.json();
  if(!r.ok){ alert(data.error||'Failed'); return; }
  commentBox.value='';
  const c = data.comment;
  const el = document.createElement('div');
  el.className='card p-3';
  el.innerHTML = `<div class="text-sm"><b>${esc(c.author_name)}</b> <span class="text-white/50">· ${(new Date(c.created_at)).toISOString().slice(0,16).replace('T',' ')} UTC</span></div><div class="mt-1 whitespace-pre-wrap">${esc(c.body)}</div>`;
  comments.prepend(el);
});

assignBtn?.addEventListener('click', async () => {
  const payload = { assignee_id: assigneeId.value.trim(), assignee_name: assigneeName.value.trim() };
  const r = await fetch(`/api/tickets/{{ t.id }}/assign`, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
  const data = await r.json();
  if(!r.ok){ alert(data.error||'Failed'); return; }
  location.reload();
});

document.querySelectorAll('[data-status]')?.forEach(btn => {
  btn.addEventListener('click', async () => {
    const status = btn.dataset.status;
    const r = await fetch(`/api/tickets/${ticketId}/status`, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({status})});
    const data = await r.json();
    if(!r.ok){ alert(data.error||'Failed'); return; }
    location.reload();
  });
});
</script>
{% endblock %}
"""



ADMIN_TICKET_NEW_HTML = r"""{% extends "base.html" %}
{% block title %}New Ticket — {{ brand }}{% endblock %}
{% block content %}
<h1 class="text-2xl font-bold">Create Ticket</h1>
<form method="post" class="mt-4 grid gap-3 max-w-2xl">
  <div>
    <label class="text-xs text-white/60">Title</label>
    <input name="title" class="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2" required />
  </div>
  <div>
    <label class="text-xs text-white/60">Description</label>
    <textarea name="description" rows="8" class="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2" required></textarea>
  </div>
  <div class="grid grid-cols-2 gap-3">
    <div>
      <label class="text-xs text-white/60">Priority</label>
      <select name="priority" class="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2">
        {% for p in ['low','normal','high','urgent'] %}<option value="{{p}}">{{p.title()}}</option>{% endfor %}
      </select>
    </div>
    <div>
      <label class="text-xs text-white/60">Labels (comma-sep)</label>
      <input name="labels" class="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2" placeholder="frontend, bug, outreach" />
    </div>
  </div>
  <div class="grid grid-cols-2 gap-3">
    <div>
      <label class="text-xs text-white/60">Assignee Discord ID (optional)</label>
      <input name="assignee_id" class="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2" />
    </div>
    <div>
      <label class="text-xs text-white/60">Assignee Display Name (optional)</label>
      <input name="assignee_name" class="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2" />
    </div>
  </div>
  <div class="mt-2"><button class="btn-accent">Create Ticket</button></div>
</form>
{% endblock %}
"""

ADMIN_TICKET_EDIT_HTML = r"""{% extends "base.html" %}
{% block title %}Edit Ticket — {{ brand }}{% endblock %}
{% block content %}
<h1 class="text-2xl font-bold">Edit Ticket #{{ t.id }}</h1>
<form method="post" class="mt-4 grid gap-3 max-w-2xl">
  <div>
    <label class="text-xs text-white/60">Title</label>
    <input name="title" value="{{ t.title }}" class="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2" required />
  </div>
  <div>
    <label class="text-xs text-white/60">Description</label>
    <textarea name="description" rows="8" class="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2" required>{{ t.description }}</textarea>
  </div>
  <div class="grid grid-cols-2 gap-3">
    <div>
      <label class="text-xs text-white/60">Priority</label>
      <select name="priority" class="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2">
        {% for p in ['low','normal','high','urgent'] %}<option value="{{p}}" {{ 'selected' if t.priority==p else '' }}>{{p.title()}}</option>{% endfor %}
      </select>
    </div>
    <div>
      <label class="text-xs text-white/60">Labels (comma-sep)</label>
      <input name="labels" value="{{ ', '.join(t.label_list()) }}" class="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2" />
    </div>
  </div>
  <div class="grid grid-cols-2 gap-3">
    <div>
      <label class="text-xs text-white/60">Assignee Discord ID</label>
      <input name="assignee_id" value="{{ t.assignee_id or '' }}" class="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2" />
    </div>
    <div>
      <label class="text-xs text-white/60">Assignee Display Name</label>
      <input name="assignee_name" value="{{ t.assignee_name or '' }}" class="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2" />
    </div>
  </div>
  <div>
    <label class="text-xs text-white/60">Status</label>
    <select name="status" class="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2">
      {% for s in ['open','in_progress','done','cancelled'] %}<option value="{{s}}" {{ 'selected' if t.status==s else '' }}>{{ s.replace('_',' ').title() }}</option>{% endfor %}
    </select>
  </div>
  <div class="mt-2"><button class="btn-accent">Save Changes</button></div>
</form>
{% endblock %}
"""

def _ensure_template_files():
    tpl_dir = ROOT / "templates"
    tpl_dir.mkdir(parents=True, exist_ok=True)
    files = {
        tpl_dir / "base.html": BASE_HTML,
        tpl_dir / "join_form.html": JOIN_FORM_HTML,
        tpl_dir / "join_thanks.html": JOIN_THANKS_HTML,
        tpl_dir / "tickets.html": TICKETS_HTML,
        tpl_dir / "ticket_detail.html": TICKET_DETAIL_HTML,
        tpl_dir / "admin_ticket_new.html": ADMIN_TICKET_NEW_HTML,
        tpl_dir / "admin_ticket_edit.html": ADMIN_TICKET_EDIT_HTML,
    }
    for p, content in files.items():
        if content and not p.exists():
            p.write_text(content, encoding="utf-8")

# Write templates + init DB at import time so Gunicorn workers are ready
_ensure_template_files()
init_db()

if __name__ == "__main__":
    app.run(debug=True, port=5000)

