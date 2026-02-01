import os
import json
from typing import Optional, Literal, List, Dict, Any

import jwt
from jwt import InvalidTokenError
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from psycopg import connect
from psycopg.rows import dict_row

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:5HeY6LhFHx9aqxwX@db.hgishjwhpvfxsmvtjgbf.supabase.co:5432/postgres")
SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET", "hb+dVcUH1Qk5e6W5d3WSNMqmqALEy41WONR3jJ2kAE3MYa1TTVtVVCRTAPUTgcRnFzlqQc1iO6nBtW3Aj3Wivw==")
ENV = os.getenv("ENV", "prod")

AppRole = Literal["SALARIE", "CHEF_CHANTIER", "RESPONSABLE"]

app = FastAPI(title="Planning API (MVP)")

# CORS: au début on autorise tout. Après tu mettras ton domaine Cloudflare Pages.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if ENV != "prod" else ["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------
# Utils DB
# --------------------------
def db_conn():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL missing")
    return connect(DATABASE_URL, row_factory=dict_row)


# --------------------------
# Auth: vérification JWT Supabase
# --------------------------
def decode_supabase_jwt(token: str) -> Dict[str, Any]:
    """
    Token = access_token retourné par Supabase Auth.
    On vérifie la signature HS256 avec SUPABASE_JWT_SECRET.
    """
    if not SUPABASE_JWT_SECRET:
        raise RuntimeError("SUPABASE_JWT_SECRET missing")

    try:
        payload = jwt.decode(
            token,
            SUPABASE_JWT_SECRET,
            algorithms=["HS256"],
            options={
                "verify_aud": False,  # on ne force pas l'audience pour MVP
            },
        )
        return payload
    except InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def get_bearer_token(authorization: Optional[str] = Header(None)) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    parts = authorization.split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Authorization must be: Bearer <token>")
    return parts[1].strip()


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
# Health
# --------------------------
@app.get("/health")
def health():
    return {"ok": True}


# --------------------------
# Employees
# - SALARIE: read only self
# - CHEF_CHANTIER: read all
# - RESPONSABLE: read/write all
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
                  where id = %s
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
# - SALARIE: read only self
# - CHEF_CHANTIER: read all, create/update BROUILLON/SOUMIS
# - RESPONSABLE: all + can set VALIDE/REFUSE
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
        where.append("a.activity = %s")
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
    # Champs requis
    required = ["employee_id", "activity", "assign_date", "role", "shift", "status"]
    for k in required:
        if k not in payload:
            raise HTTPException(status_code=400, detail=f"Missing field: {k}")

    # Chef: seulement BROUILLON/SOUMIS
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
                # unique index 1 assignment/day -> erreur ici si conflit
                raise HTTPException(status_code=400, detail=f"Insert failed: {str(e)}")


@app.patch("/assignments/{assignment_id}")
def update_assignment(assignment_id: str, payload: Dict[str, Any], user=Depends(require_roles("CHEF_CHANTIER", "RESPONSABLE"))):
    # On lit le status actuel
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select status::text from public.assignments where id = %s::uuid", (assignment_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Assignment not found")
            current_status = row["status"]

            # Chef ne peut modifier que si BROUILLON/SOUMIS
            if user["role"] == "CHEF_CHANTIER" and current_status not in ("BROUILLON", "SOUMIS"):
                raise HTTPException(status_code=403, detail="Chef cannot edit after validation/refusal")

            # Chef ne peut pas setter VALIDE/REFUSE
            if user["role"] == "CHEF_CHANTIER" and "status" in payload and payload["status"] in ("VALIDE", "REFUSE"):
                raise HTTPException(status_code=403, detail="Chef cannot validate/refuse")

            # Build update dynamically
            allowed_fields = {"activity","assign_date","role","shift","is_pf","status"}
            sets = []
            params = []
            for k, v in payload.items():
                if k not in allowed_fields:
                    continue
                if k == "activity":
                    sets.append("activity = %s::activity_type"); params.append(v)
                elif k == "assign_date":
                    sets.append("assign_date = %s::date"); params.append(v)
                elif k == "role":
                    sets.append("role = %s::role_code"); params.append(v)
                elif k == "shift":
                    sets.append("shift = %s::shift_code"); params.append(v)
                elif k == "is_pf":
                    sets.append("is_pf = %s::boolean"); params.append(bool(v))
                elif k == "status":
                    sets.append("status = %s::request_status"); params.append(v)

            if not sets:
                return {"ok": True, "updated": 0}

            params.append(assignment_id)
            cur.execute(f"update public.assignments set {', '.join(sets)} where id = %s::uuid", tuple(params))
            conn.commit()
            return {"ok": True, "updated": cur.rowcount}


# --------------------------
# Unavailabilities (congé/RTT/maladie/formation/roulage)
# - SALARIE: create/update only self in BROUILLON/SOUMIS
# - RESPONSABLE: all
# --------------------------
@app.get("/unavailabilities")
def list_unavail(
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    user=Depends(get_current_user),
):
    where = []
    params = []
    if date_from:
        where.append("u.start_date >= %s::date"); params.append(date_from)
    if date_to:
        where.append("u.end_date <= %s::date"); params.append(date_to)

    if user["role"] == "SALARIE":
        if not user["employee_id"]:
            return []
        where.append("u.employee_id = %s::uuid"); params.append(user["employee_id"])

    sql = """
      select
        u.id::text, u.employee_id::text, e.first_name, e.last_name,
        u.type::text, u.impact::text,
        u.start_date::text, u.end_date::text,
        u.start_time::text, u.end_time::text,
        u.status::text
      from public.unavailabilities u
      join public.employees e on e.id = u.employee_id
    """
    if where:
        sql += " where " + " and ".join(where)
    sql += " order by u.start_date"

    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, tuple(params))
            return cur.fetchall()


@app.post("/unavailabilities")
def create_unavail(payload: Dict[str, Any], user=Depends(get_current_user)):
    required = ["employee_id","type","start_date","end_date","impact","status"]
    for k in required:
        if k not in payload:
            raise HTTPException(status_code=400, detail=f"Missing field: {k}")

    # SALARIE: seulement sur lui-même + BROUILLON/SOUMIS
    if user["role"] == "SALARIE":
        if not user["employee_id"] or payload["employee_id"] != user["employee_id"]:
            raise HTTPException(status_code=403, detail="SALARIE can only create for self")
        if payload["status"] not in ("BROUILLON","SOUMIS"):
            raise HTTPException(status_code=403, detail="SALARIE can only create BROUILLON/SOUMIS")

    # CHEF_CHANTIER: on bloque (MVP) => il ne crée pas d'indispo, seulement admin + salarié
    if user["role"] == "CHEF_CHANTIER":
        raise HTTPException(status_code=403, detail="CHEF_CHANTIER cannot create unavailabilities (MVP)")

    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
              insert into public.unavailabilities(
                employee_id, type, start_date, end_date, start_time, end_time, impact, status, requested_by
              )
              values (%s::uuid, %s::unavailability_type, %s::date, %s::date,
                      %s::time, %s::time, %s::availability_impact, %s::request_status, %s::uuid)
              returning id::text
            """, (
                payload["employee_id"],
                payload["type"],
                payload["start_date"],
                payload["end_date"],
                payload.get("start_time"),
                payload.get("end_time"),
                payload["impact"],
                payload["status"],
                user["user_id"],
            ))
            new_id = cur.fetchone()["id"]
            conn.commit()
            return {"id": new_id}


# --------------------------
# Alerts
# (lecture des vues)
# --------------------------
@app.get("/alerts/coverage/daily")
def alerts_coverage_daily(activity: str = "ME1", limit: int = 60, user=Depends(require_roles("CHEF_CHANTIER","RESPONSABLE"))):
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
              select activity::text, day_date::text, mode::text, missing_total, missing_items
              from public.v_coverage_alerts_daily_summary
              where activity = %s
              order by day_date
              limit %s
            """, (activity, limit))
            return cur.fetchall()


@app.get("/alerts/medical")
def alerts_medical(limit: int = 200, user=Depends(require_roles("CHEF_CHANTIER","RESPONSABLE"))):
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
              select employee_id::text, first_name, last_name, visit_type_code, visit_type_label,
                     visit_date::text, expires_on::text, alert_level
              from public.v_medical_visit_alerts
              where alert_level in ('EXPIRE','J_30','J_60')
              order by expires_on nulls last
              limit %s
            """, (limit,))
            return cur.fetchall()
