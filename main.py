import os
from typing import Optional, Literal, Dict, Any

import jwt
from jwt import InvalidTokenError, PyJWKClient
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from psycopg import connect
from psycopg.rows import dict_row

# --------------------------
# ENV
# --------------------------
DATABASE_URL = os.getenv("DATABASE_URL", "")
SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET", "")
SUPABASE_PROJECT_URL = os.getenv("SUPABASE_PROJECT_URL", "").rstrip("/")
ENV = os.getenv("ENV", "prod")

AppRole = Literal["SALARIE", "CHEF_CHANTIER", "RESPONSABLE"]

app = FastAPI(title="Planning API (MVP)")

# CORS: au début on laisse "*". Plus tard, restreins à ton domaine Cloudflare Pages.
from fastapi.responses import Response

FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "").strip()

origins = ["*"] if not FRONTEND_ORIGIN else [FRONTEND_ORIGIN]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "apikey"],
)


# --------------------------
# DB helper
# --------------------------
def db_conn():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL missing (set it in Render env vars)")
    return connect(DATABASE_URL, row_factory=dict_row)


# --------------------------
# Auth helpers
# --------------------------
def get_bearer_token(authorization: Optional[str] = Header(None)) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    parts = authorization.split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Authorization must be: Bearer <token>")
    return parts[1].strip()


def decode_supabase_jwt(token: str) -> Dict[str, Any]:
    """
    Supporte:
      - HS256 (secret)
      - RS256 (JWKS)
      - ES256 (JWKS)  <-- ton cas
    """
    try:
        header = jwt.get_unverified_header(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token header")

    alg = header.get("alg")

    # HS256: vérification via secret
    if alg == "HS256":
        if not SUPABASE_JWT_SECRET:
            raise RuntimeError("SUPABASE_JWT_SECRET missing (Render env var)")
        try:
            return jwt.decode(
                token,
                SUPABASE_JWT_SECRET,
                algorithms=["HS256"],
                options={"verify_aud": False},
            )
        except InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid or expired token")

    # RS256 / ES256: vérification via JWKS (clé publique Supabase)
    if alg in ("RS256", "ES256"):
        if not SUPABASE_PROJECT_URL:
            raise RuntimeError("SUPABASE_PROJECT_URL missing (Render env var)")
        jwks_url = f"{SUPABASE_PROJECT_URL}/auth/v1/.well-known/jwks.json"
        try:
            jwk_client = PyJWKClient(jwks_url)
            signing_key = jwk_client.get_signing_key_from_jwt(token).key
            return jwt.decode(
                token,
                signing_key,
                algorithms=[alg],
                options={"verify_aud": False},
            )
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid or expired token")

    raise HTTPException(status_code=401, detail=f"Unsupported JWT alg: {alg}")


def get_current_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    token = get_bearer_token(authorization)
    payload = decode_supabase_jwt(token)

    user_id = payload.get("sub")
    email = payload.get("email")
    if not user_id:
        raise HTTPException(status_code=401, detail="Token missing 'sub'")

    # Lire role + employee_id depuis user_profiles
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select user_id::text, role::text, employee_id::text, display_name, is_active
                from public.user_profiles
                where user_id = %s
                """,
                (user_id,),
            )
            profile = cur.fetchone()

    if not profile:
        raise HTTPException(
            status_code=403,
            detail="No profile found. Create user_profiles row for this user.",
        )
    if profile["is_active"] is False:
        raise HTTPException(status_code=403, detail="User profile disabled")

    return {
        "user_id": profile["user_id"],
        "email": email,
        "role": profile["role"],
        "employee_id": profile["employee_id"],
        "display_name": profile["display_name"],
    }


def require_roles(*allowed: AppRole):
    def _dep(user=Depends(get_current_user)):
        if user["role"] not in allowed:
            raise HTTPException(status_code=403, detail=f"Forbidden for role: {user['role']}")
        return user
    return _dep


# --------------------------
# ROUTES
# --------------------------
@app.get("/")
def root():
    return {"service": "planning-api", "status": "ok", "docs": "/docs"}


@app.get("/health")
def health():
    return {"ok": True}


# --------------------------
# Employees
# --------------------------
@app.get("/employees")
def list_employees(user=Depends(get_current_user)):
    with db_conn() as conn:
        with conn.cursor() as cur:
            if user["role"] in ("CHEF_CHANTIER", "RESPONSABLE"):
                cur.execute("""
                  select id::text, first_name, last_name, email, phone, is_active
                  from public.employees
                  where is_active=true
                  order by last_name, first_name
                """)
                return cur.fetchall()
            else:
                if not user["employee_id"]:
                    return []
                cur.execute("""
                  select id::text, first_name, last_name, email, phone, is_active
                  from public.employees
                  where id = %s::uuid
                """, (user["employee_id"],))
                row = cur.fetchone()
                return [row] if row else []


@app.post("/employees")
def create_employee(payload: Dict[str, Any], user=Depends(require_roles("RESPONSABLE"))):
    required = ["first_name", "last_name"]
    for k in required:
        if k not in payload or not str(payload[k]).strip():
            raise HTTPException(status_code=400, detail=f"Missing field: {k}")

    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
              insert into public.employees(first_name,last_name,email,phone,is_active)
              values (%s,%s,%s,%s,true)
              returning id::text
            """, (
                payload["first_name"].strip(),
                payload["last_name"].strip(),
                payload.get("email"),
                payload.get("phone"),
            ))
            new_id = cur.fetchone()["id"]
        conn.commit()
    return {"id": new_id}


# --------------------------
# Assignments
# --------------------------
@app.get("/assignments")
def list_assignments(
    activity: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    user=Depends(get_current_user),
):
    where = []
    params = []

    if activity:
        where.append("a.activity = %s::activity_type")
        params.append(activity)
    if date_from:
        where.append("a.assign_date >= %s::date")
        params.append(date_from)
    if date_to:
        where.append("a.assign_date <= %s::date")
        params.append(date_to)

    if user["role"] == "SALARIE":
        if not user["employee_id"]:
            return []
        where.append("a.employee_id = %s::uuid")
        params.append(user["employee_id"])

    sql = """
      select
        a.id::text,
        a.employee_id::text,
        e.first_name,
        e.last_name,
        a.activity::text,
        a.assign_date::text,
        a.role::text,
        a.shift::text,
        a.is_pf,
        a.status::text
      from public.assignments a
      join public.employees e on e.id = a.employee_id
    """
    if where:
        sql += " where " + " and ".join(where)
    sql += " order by a.assign_date, a.activity, a.role, a.shift"

    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, tuple(params))
            return cur.fetchall()


@app.post("/assignments")
def create_assignment(payload: Dict[str, Any], user=Depends(require_roles("CHEF_CHANTIER", "RESPONSABLE"))):
    required = ["employee_id", "activity", "assign_date", "role", "shift", "status"]
    for k in required:
        if k not in payload:
            raise HTTPException(status_code=400, detail=f"Missing field: {k}")

    if user["role"] == "CHEF_CHANTIER" and payload["status"] not in ("BROUILLON", "SOUMIS"):
        raise HTTPException(status_code=403, detail="Chef can only create BROUILLON/SOUMIS assignments")

    with db_conn() as conn:
        with conn.cursor() as cur:
            try:
                cur.execute("""
                  insert into public.assignments(
                    employee_id, activity, assign_date, role, shift, is_pf, status, created_by
                  )
                  values (%s::uuid, %s::activity_type, %s::date, %s::role_code, %s::shift_code,
                          %s::boolean, %s::request_status, %s::uuid)
                  returning id::text
                """, (
                    payload["employee_id"],
                    payload["activity"],
                    payload["assign_date"],
                    payload["role"],
                    payload["shift"],
                    bool(payload.get("is_pf", False)),
                    payload["status"],
                    user["user_id"],
                ))
                new_id = cur.fetchone()["id"]
                conn.commit()
                return {"id": new_id}
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Insert failed: {str(e)}")


# --------------------------
# Alerts
# --------------------------
@app.get("/alerts/coverage/daily")
def alerts_coverage_daily(
    activity: str = "ME1",
    limit: int = 60,
    user=Depends(require_roles("CHEF_CHANTIER", "RESPONSABLE")),
):
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
              select activity::text, day_date::text, mode::text, missing_total, missing_items
              from public.v_coverage_alerts_daily_summary
              where activity = %s::activity_type
              order by day_date
              limit %s
            """, (activity, limit))
            return cur.fetchall()
