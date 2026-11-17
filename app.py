import hmac
import json
import logging
import math
import os
import secrets
from json import JSONDecodeError
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

import bcrypt
from dotenv import load_dotenv
from flask import Flask, abort, redirect, render_template, request, session, url_for


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
ALLOW_NO_AUTH_DASHBOARD = os.environ.get("ALLOW_NO_AUTH_DASHBOARD", "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SupabaseError(Exception):
    pass


MANAGED_TABLES = {
    "tours": {
        "table": "tours",
        "title": "Аялал",
        "singular": "аялал",
        "search_fields": ("name", "destination", "description"),
        "fields": (
            {"name": "name", "label": "Аяллын нэр", "type": "text", "required": True},
            {"name": "destination", "label": "Чиглэл", "type": "text", "required": True},
            {"name": "duration_days", "label": "Хоног", "type": "number", "required": True},
            {"name": "price", "label": "Үнэ (₮)", "type": "number", "required": True},
            {"name": "description", "label": "Тайлбар", "type": "textarea", "required": False},
        ),
    },
    "staff": {
        "table": "staff",
        "title": "Ажилтан",
        "singular": "ажилтан",
        "search_fields": ("name", "role", "email", "phone"),
        "fields": (
            {"name": "name", "label": "Нэр", "type": "text", "required": True},
            {"name": "role", "label": "Албан тушаал", "type": "text", "required": True},
            {"name": "email", "label": "И-мэйл", "type": "email", "required": True},
            {"name": "phone", "label": "Утас", "type": "text", "required": False},
        ),
    },
}


def supabase_request(
    method: str,
    table: str,
    query: dict[str, str] | None = None,
    payload: dict[str, Any] | None = None,
) -> Any:
    project_url = os.environ.get("SUPABASE_URL", "").strip().rstrip("/")
    secret_key = os.environ.get("SUPABASE_SECRET_KEY", "").strip()
    parsed_url = urlsplit(project_url)

    if parsed_url.scheme != "https" or not parsed_url.netloc:
        raise SupabaseError(
            "SUPABASE_URL-д Supabase төслийн https://... хаягийг оруулна уу."
        )
    if not (secret_key.startswith("sb_secret_") or secret_key.startswith("eyJ")):
        raise SupabaseError(
            "SUPABASE_SECRET_KEY-д secret/service_role түлхүүр оруулна уу. "
            "Publishable/anon түлхүүр тохирохгүй."
        )

    endpoint = f"{project_url}/rest/v1/{table}"
    if query:
        endpoint = f"{endpoint}?{urlencode(query)}"
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {
        "apikey": secret_key,
        "Authorization": f"Bearer {secret_key}",
        "Accept-Profile": "public",
        "Accept": "application/json",
    }
    if body is not None:
        headers["Content-Type"] = "application/json"
        headers["Content-Profile"] = "public"
    if method in {"POST", "PATCH", "DELETE"}:
        headers["Prefer"] = "return=minimal"
    req = Request(
        endpoint,
        data=body,
        headers=headers,
        method=method,
    )
    try:
        with urlopen(req, timeout=15) as response:
            response_body = response.read()
            return json.loads(response_body) if response_body else None
    except HTTPError as exc:
        error_detail = exc.read().decode("utf-8", "replace")
        detail = f" ({error_detail[:200]})" if error_detail else ""
        raise SupabaseError(
            f"Supabase хүсэлт амжилтгүй боллоо (HTTP {exc.code}).{detail}"
        ) from None
    except URLError:
        raise SupabaseError("Supabase-тай холбогдож чадсангүй.") from None
    except JSONDecodeError:
        raise SupabaseError("Supabase-ээс унших боломжгүй хариу ирлээ.") from None


def supabase_get(table: str, query: dict[str, str]) -> list[dict[str, Any]]:
    data = supabase_request("GET", table, query=query)
    if not isinstance(data, list) or not all(isinstance(row, dict) for row in data):
        raise SupabaseError("Supabase-ээс хүлээсэн өгөгдлийн хэлбэр ирсэнгүй.")
    return data


def supabase_update(table: str, row_id: Any, updates: dict[str, Any]) -> None:
    supabase_request("PATCH", table, {"id": f"eq.{row_id}"}, updates)


def supabase_insert(table: str, values: dict[str, Any]) -> None:
    supabase_request("POST", table, payload=values)


def supabase_delete(table: str, row_id: int) -> None:
    supabase_request("DELETE", table, {"id": f"eq.{row_id}"})


def csrf_token() -> str:
    token = session.get("csrf_token")
    if not isinstance(token, str):
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def valid_csrf_token() -> bool:
    submitted = request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")
    return isinstance(expected, str) and hmac.compare_digest(submitted, expected)


@app.get("/")
def home():
    if session.get("user_email") or ALLOW_NO_AUTH_DASHBOARD:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_email"):
        return redirect(url_for("dashboard"))

    error = None
    if request.method == "POST":
        if not valid_csrf_token():
            error = "Хүсэлт баталгаажаагүй байна. Хуудсаа шинэчлээд дахин оролдоно уу."
        else:
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            try:
                users = supabase_get(
                    "users",
                    {
                        "select": "email,password_hash",
                        "email": f"eq.{email}",
                        "limit": "1",
                    },
                )
                user = users[0] if users else None
                password_bytes = password.encode("utf-8")
                if (
                    user is not None
                    and len(password_bytes) <= 72
                    and isinstance(user.get("email"), str)
                    and isinstance(user.get("password_hash"), str)
                    and bcrypt.checkpw(
                        password_bytes, user["password_hash"].encode("ascii")
                    )
                ):
                    session.clear()
                    session["user_email"] = user["email"]
                    csrf_token()
                    return redirect(url_for("dashboard"))
                error = "И-мэйл эсвэл нууц үг буруу байна."
            except SupabaseError as exc:
                logger.warning("Supabase login request failed: %s", exc)
                error = str(exc)
            except (UnicodeEncodeError, ValueError):
                logger.exception("Could not verify the stored password hash.")
                error = "Хэрэглэгчийн нууц үгийг шалгахад алдаа гарлаа."

    return render_template("login.html", error=error, csrf_token=csrf_token())


@app.get("/dashboard")
def dashboard():
    email = session.get("user_email")
    if not isinstance(email, str):
        if not ALLOW_NO_AUTH_DASHBOARD:
            return redirect(url_for("login"))
        email = "test@whale.local"

    session_error = session.pop("draft_action_error", None)
    try:
        drafts = supabase_get(
            "content_drafts",
            {
                "select": "id,title,content,status,created_at",
                "status": "eq.draft",
                "order": "created_at.desc",
            },
        )
        error = session_error
    except SupabaseError as exc:
        logger.warning("Supabase drafts request failed: %s", exc)
        drafts = []
        error = session_error or str(exc)

    return render_template(
        "dashboard.html",
        email=email,
        drafts=drafts,
        error=error,
        csrf_token=csrf_token(),
    )


def managed_config(entity: str) -> dict[str, Any]:
    config = MANAGED_TABLES.get(entity)
    if config is None:
        abort(404)
    return config


def get_managed_record(config: dict[str, Any], record_id: int) -> dict[str, Any]:
    rows = supabase_get(
        config["table"],
        {"select": "*", "id": f"eq.{record_id}", "limit": "1"},
    )
    if not rows:
        abort(404)
    return rows[0]


def read_managed_values(config: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    values: dict[str, Any] = {}
    for field in config["fields"]:
        raw_value = request.form.get(field["name"], "").strip()
        if field["required"] and not raw_value:
            return values, f"«{field['label']}» талбарыг бөглөнө үү."
        if len(raw_value) > 5000:
            return values, f"«{field['label']}» талбар хэт урт байна."
        if not raw_value:
            values[field["name"]] = None if field["name"] == "phone" else ""
        elif field["name"] == "duration_days":
            try:
                values[field["name"]] = int(raw_value)
            except ValueError:
                return values, "Хоногийн тоог бүхэл тоогоор оруулна уу."
            if values[field["name"]] < 1:
                return values, "Хоногийн тоо 1-ээс багагүй байна."
        elif field["name"] == "price":
            try:
                price = float(raw_value)
            except ValueError:
                return values, "Үнийг зөв тоогоор оруулна уу."
            if not math.isfinite(price) or price < 0:
                return values, "Үнэ 0-ээс багагүй зөв тоо байна."
            values[field["name"]] = price
        elif field["name"] == "email" and "@" not in raw_value:
            return values, "И-мэйл хаягаа зөв оруулна уу."
        else:
            values[field["name"]] = raw_value
    return values, None


@app.get("/manage/<string:entity>")
def manage_records(entity: str):
    config = managed_config(entity)
    email = session.get("user_email")
    if not isinstance(email, str):
        if not ALLOW_NO_AUTH_DASHBOARD:
            return redirect(url_for("login"))
        email = "test@whale.local"

    search = request.args.get("q", "").strip()
    error = session.pop("manage_error", None)
    success = session.pop("manage_success", None)
    try:
        records = supabase_get(config["table"], {"select": "*", "order": "created_at.desc"})
        if search:
            needle = search.casefold()
            records = [
                record for record in records
                if any(
                    needle in str(record.get(field) or "").casefold()
                    for field in config["search_fields"]
                )
            ]
    except SupabaseError as exc:
        logger.warning("Supabase %s list request failed: %s", entity, exc)
        records = []
        error = error or str(exc)

    return render_template(
        "manage.html",
        email=email,
        entity=entity,
        config=config,
        records=records,
        search=search,
        error=error,
        success=success,
        csrf_token=csrf_token(),
    )


@app.route("/manage/<string:entity>/new", methods=["GET", "POST"])
def add_managed_record(entity: str):
    config = managed_config(entity)
    values = {}
    error = None
    if request.method == "POST":
        if not valid_csrf_token():
            return "Хүсэлт баталгаажаагүй байна. Хуудсаа шинэчлээд дахин оролдоно уу.", 400
        values, error = read_managed_values(config)
        if error is None:
            try:
                supabase_insert(config["table"], values)
                session["manage_success"] = f"{config['singular'].capitalize()} амжилттай нэмлээ."
                return redirect(url_for("manage_records", entity=entity))
            except SupabaseError as exc:
                logger.warning("Supabase %s insert failed: %s", entity, exc)
                error = str(exc)

    return render_template(
        "record_form.html",
        config=config,
        entity=entity,
        record=None,
        values=values,
        error=error,
        csrf_token=csrf_token(),
    ), (400 if error else 200)


@app.route("/manage/<string:entity>/<int:record_id>/edit", methods=["GET", "POST"])
def edit_managed_record(entity: str, record_id: int):
    config = managed_config(entity)
    try:
        record = get_managed_record(config, record_id)
    except SupabaseError as exc:
        logger.warning("Supabase %s record request failed: %s", entity, exc)
        abort(502, description=str(exc))

    values = record
    error = None
    if request.method == "POST":
        if not valid_csrf_token():
            return "Хүсэлт баталгаажаагүй байна. Хуудсаа шинэчлээд дахин оролдоно уу.", 400
        values, error = read_managed_values(config)
        if error is None:
            try:
                supabase_update(config["table"], record_id, values)
                session["manage_success"] = f"{config['singular'].capitalize()} амжилттай заслаа."
                return redirect(url_for("manage_records", entity=entity))
            except SupabaseError as exc:
                logger.warning("Supabase %s update failed: %s", entity, exc)
                error = str(exc)

    return render_template(
        "record_form.html",
        config=config,
        entity=entity,
        record=record,
        values=values,
        error=error,
        csrf_token=csrf_token(),
    ), (400 if error else 200)


@app.route("/manage/<string:entity>/<int:record_id>/delete", methods=["GET", "POST"])
def delete_managed_record(entity: str, record_id: int):
    config = managed_config(entity)
    try:
        record = get_managed_record(config, record_id)
    except SupabaseError as exc:
        logger.warning("Supabase %s record request failed: %s", entity, exc)
        abort(502, description=str(exc))

    if request.method == "GET":
        return render_template(
            "confirm_delete.html",
            config=config,
            entity=entity,
            record=record,
            csrf_token=csrf_token(),
        )
    if not valid_csrf_token():
        return "Хүсэлт баталгаажаагүй байна. Хуудсаа шинэчлээд дахин оролдоно уу.", 400
    if request.form.get("confirmed") != "yes":
        return "Устгахын өмнө үйлдлийг баталгаажуулна уу.", 400

    try:
        supabase_delete(config["table"], record_id)
        session["manage_success"] = f"{config['singular'].capitalize()} устгалаа."
    except SupabaseError as exc:
        logger.warning("Supabase %s delete failed: %s", entity, exc)
        session["manage_error"] = str(exc)
    return redirect(url_for("manage_records", entity=entity))


@app.post("/drafts/<int:draft_id>/<string:action>")
def update_draft_status(draft_id: int, action: str):
    if not valid_csrf_token():
        return "Хүсэлт баталгаажаагүй байна. Хуудсаа шинэчлээд дахин оролдоно уу.", 400

    mapping = {
        "approve": "published",
        "reject": "archived",
    }
    new_status = mapping.get(action)
    if new_status is None:
        return "Буруу үйлдэл байна.", 400

    try:
        supabase_update("content_drafts", draft_id, {"status": new_status})
        session.pop("draft_action_error", None)
    except SupabaseError as exc:
        session["draft_action_error"] = str(exc)
    return redirect(url_for("dashboard"))


@app.post("/logout")
def logout():
    if not valid_csrf_token():
        return "Хүсэлт баталгаажаагүй байна. Хуудсаа шинэчлээд дахин оролдоно уу.", 400
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
