#!/usr/bin/env python3
"""
ShopPilot Cloud - multi-shop stock & profit manager (pure Python 3.8+, no installs).

Run locally:   OWNER_EMAIL=you@mail.com OWNER_PASSWORD='a-long-password' python app.py
Env vars:      OWNER_EMAIL, OWNER_PASSWORD (first start only), PORT, DATA_DIR, PAY_INFO,
               ALLOW_REGISTER=1|0, BACKUP_HOURS=6, KEEP_BACKUPS=28, TZ_HOURS=3, SECURE_COOKIES=1
"""
import sqlite3, json, os, sys, re, hmac, hashlib, secrets, threading, time, glob, csv, io, traceback
import datetime as dt
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from http.cookies import SimpleCookie

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.environ.get("DATA_DIR", os.path.join(HERE, "data"))
BK = os.path.join(DATA, "backups")
os.makedirs(BK, exist_ok=True)
DB = os.path.join(DATA, "shoppilot.db")
TZH = float(os.environ.get("TZ_HOURS", "3"))  # Kenya = UTC+3
TRIAL_DAYS, SESSION_DAYS = 14, 14
BACKUP_HOURS = float(os.environ.get("BACKUP_HOURS", "6"))
KEEP = int(os.environ.get("KEEP_BACKUPS", "28"))
D = dt.date
utc = lambda: dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


def today():
    return (utc() + dt.timedelta(hours=TZH)).date().isoformat()


now = lambda: utc().isoformat(timespec="seconds")
sha = lambda s: hashlib.sha256(s.encode()).hexdigest()
rows = lambda c, q, a=(): [dict(r) for r in c.execute(q, a)]


def db():
    c = sqlite3.connect(DB, timeout=15, isolation_level=None)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA synchronous=FULL")
    return c


class tx:  # one atomic transaction: all-or-nothing
    def __enter__(s):
        s.c = db()
        s.c.execute("BEGIN IMMEDIATE")
        return s.c

    def __exit__(s, t, v, tb):
        try:
            s.c.execute("ROLLBACK" if t else "COMMIT")
        finally:
            s.c.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS shops(id INTEGER PRIMARY KEY,name TEXT NOT NULL,phone TEXT DEFAULT '',place TEXT DEFAULT '',plan_until TEXT NOT NULL,created TEXT);
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT NOT NULL UNIQUE COLLATE NOCASE,name TEXT,salt TEXT,pw TEXT,
  role TEXT NOT NULL CHECK(role IN('owner','manager','staff')),shop_id INTEGER REFERENCES shops(id),disabled INTEGER DEFAULT 0,
  fails INTEGER DEFAULT 0,locked_until INTEGER DEFAULT 0,created TEXT);
CREATE TABLE IF NOT EXISTS sessions(h TEXT PRIMARY KEY,user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,expires INTEGER);
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY,shop_id INTEGER NOT NULL REFERENCES shops(id),name TEXT NOT NULL,category TEXT DEFAULT '',
  buy REAL NOT NULL CHECK(buy>=0),sell REAL NOT NULL CHECK(sell>=0),qty REAL NOT NULL CHECK(qty>=0),minq REAL NOT NULL DEFAULT 5,archived INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS receipts(id INTEGER PRIMARY KEY,shop_id INTEGER NOT NULL,no INTEGER NOT NULL,date TEXT,ts TEXT,customer TEXT DEFAULT '',
  credit INTEGER DEFAULT 0,cashier TEXT,UNIQUE(shop_id,no));
CREATE TABLE IF NOT EXISTS sales(id INTEGER PRIMARY KEY,shop_id INTEGER NOT NULL,receipt_id INTEGER,date TEXT,pid INTEGER,pname TEXT,
  qty REAL CHECK(qty>0),price REAL CHECK(price>=0),cost REAL,customer TEXT DEFAULT '',voided INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS purchases(id INTEGER PRIMARY KEY,shop_id INTEGER NOT NULL,date TEXT,pid INTEGER,pname TEXT,qty REAL,cost REAL,supplier TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS expenses(id INTEGER PRIMARY KEY,shop_id INTEGER NOT NULL,date TEXT,cat TEXT,note TEXT,amount REAL CHECK(amount>=0));
CREATE TABLE IF NOT EXISTS debts(id INTEGER PRIMARY KEY,shop_id INTEGER NOT NULL,date TEXT,party TEXT,kind TEXT CHECK(kind IN('owed','owe')),
  amount REAL CHECK(amount>=0),paid REAL DEFAULT 0 CHECK(paid>=0),note TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS payments(id INTEGER PRIMARY KEY,shop_id INTEGER,date TEXT,amount REAL,ref TEXT,days INTEGER);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,ts TEXT,shop_id INTEGER,user_id INTEGER,action TEXT,detail TEXT);
CREATE INDEX IF NOT EXISTS ix_sales ON sales(shop_id,date);
CREATE INDEX IF NOT EXISTS ix_sales_r ON sales(receipt_id);
CREATE INDEX IF NOT EXISTS ix_exp ON expenses(shop_id,date);
CREATE INDEX IF NOT EXISTS ix_prod ON products(shop_id,archived);
"""


def init():
    c = db()
    c.executescript(SCHEMA)
    ok = c.execute("PRAGMA integrity_check").fetchone()[0]
    c.close()
    if ok != "ok":
        print("WARNING: database integrity check failed:", ok)


# ---------- validation helpers ----------
def clean(v, n, req=False, label="Value"):
    s = re.sub(r"[\x00-\x1f\x7f]", "", str(v if v is not None else "")).strip()[:n]
    if req and not s:
        raise ValueError(f"{label} is required")
    return s


def num(v, name, lo=0.0, hi=1e9):
    try:
        n = float(v)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be a number")
    if n != n or n < lo or n > hi:
        raise ValueError(f"{name} must be between {lo:g} and {hi:g}")
    return round(n, 2)


def dstr(v, default=None):
    try:
        return D.fromisoformat(str(v or default)[:10]).isoformat()
    except ValueError:
        raise ValueError("Invalid date")


def email(v):
    e = clean(v, 120).lower()
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", e):
        raise ValueError("Enter a valid email address")
    return e


def pwrule(p):
    if len(p or "") < 8:
        raise ValueError("Password must be at least 8 characters")
    if len(p) > 200:
        raise ValueError("Password is too long")


def hp(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 240000).hex()


def mkpw(pw):
    s = secrets.token_hex(16)
    return s, hp(pw, s)


def audit(c, sid, uid, action, detail=""):
    c.execute("INSERT INTO audit(ts,shop_id,user_id,action,detail) VALUES(?,?,?,?,?)", (now(), sid, uid, action, json.dumps(detail, default=str)[:1000]))


pub = lambda u: {"id": u["id"], "name": u["name"], "email": u["email"], "role": u["role"]}


# ---------- accounts ----------
def ensure_owner():
    with tx() as c:
        if c.execute("SELECT 1 FROM users WHERE role='owner'").fetchone():
            return
        em = os.environ.get("OWNER_EMAIL", "owner@shoppilot.local").strip().lower()
        pw, gen = os.environ.get("OWNER_PASSWORD"), False
        if not pw:
            pw, gen = secrets.token_urlsafe(10), True
        elif len(pw) < 8:
            sys.exit("OWNER_PASSWORD must be at least 8 characters.")
        s, h = mkpw(pw)
        c.execute("INSERT INTO users(email,name,salt,pw,role,created) VALUES(?,?,?,?,'owner',?)", (em, "Owner", s, h, now()))
    if gen:
        print(f"\n  OWNER ACCOUNT CREATED\n  email:    {em}\n  password: {pw}\n  Log in and change this password immediately.\n")


def new_session(c, uid):
    t = secrets.token_urlsafe(32)
    c.execute("INSERT INTO sessions VALUES(?,?,?)", (sha(t), uid, int(time.time()) + SESSION_DAYS * 86400))
    return t


def user_from(c, tok):
    if not tok:
        return None
    r = c.execute("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.h=? AND s.expires>? AND u.disabled=0", (sha(tok), int(time.time()))).fetchone()
    return dict(r) if r else None


IPF, REG = {}, {}


def login(c, b, ip):
    em, pw = clean(b.get("email"), 120).lower(), str(b.get("password") or "")[:200]
    f = IPF.get(ip, [0, time.time()])
    if time.time() - f[1] > 900:
        f = [0, time.time()]
    if f[0] >= 20:
        return None, None, "Too many attempts. Try again in 15 minutes."
    u = c.execute("SELECT * FROM users WHERE email=?", (em,)).fetchone()
    if u and u["locked_until"] > time.time():
        return None, None, "Account temporarily locked. Try again in 15 minutes."
    ok = bool(u) and hmac.compare_digest(hp(pw, u["salt"]), u["pw"]) and not u["disabled"]
    if not u:
        hp(pw, "00" * 16)  # keep timing similar
    if not ok:
        f[0] += 1
        IPF[ip] = f
        if u:
            n = u["fails"] + 1
            c.execute("UPDATE users SET fails=?,locked_until=? WHERE id=?", (0 if n >= 5 else n, int(time.time()) + 900 if n >= 5 else 0, u["id"]))
        return None, None, "Wrong email or password"
    c.execute("UPDATE users SET fails=0,locked_until=0 WHERE id=?", (u["id"],))
    return dict(u), new_session(c, u["id"]), None


def register(c, b, ip):
    if os.environ.get("ALLOW_REGISTER", "1") != "1":
        raise ValueError("Registration is closed")
    r = REG.get(ip, [0, time.time()])
    if time.time() - r[1] > 3600:
        r = [0, time.time()]
    if r[0] >= 10:
        raise ValueError("Too many sign-ups from this network. Try again later.")
    REG[ip] = [r[0] + 1, r[1]]
    name, shop, em, pw = clean(b.get("name"), 60, True, "Your name"), clean(b.get("shop"), 60, True, "Shop name"), email(b.get("email")), str(b.get("password") or "")
    pwrule(pw)
    if c.execute("SELECT 1 FROM users WHERE email=?", (em,)).fetchone():
        raise ValueError("That email is already registered")
    until = (D.fromisoformat(today()) + dt.timedelta(days=TRIAL_DAYS)).isoformat()
    sid = c.execute("INSERT INTO shops(name,plan_until,created) VALUES(?,?,?)", (shop, until, now())).lastrowid
    s, h = mkpw(pw)
    uid = c.execute("INSERT INTO users(email,name,salt,pw,role,shop_id,created) VALUES(?,?,?,?,'manager',?,?)", (em, name, s, h, sid, now())).lastrowid
    return dict(c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()), new_session(c, uid)


# ---------- shop data ----------
def stats(c, sid, d):
    r = c.execute("SELECT COALESCE(SUM(qty*price),0) r,COALESCE(SUM(qty*(price-cost)),0) g FROM sales WHERE shop_id=? AND voided=0 AND date=?", (sid, d)).fetchone()
    e = c.execute("SELECT COALESCE(SUM(amount),0) FROM expenses WHERE shop_id=? AND date=?", (sid, d)).fetchone()[0]
    return {"sales": round(r["r"], 2), "gross": round(r["g"], 2), "expenses": e, "net": round(r["g"] - e, 2)}


def data(c, u, shop):
    sid, t, staff = shop["id"], today(), u["role"] == "staff"
    week = [] if staff else [{"d": (D.fromisoformat(t) - dt.timedelta(days=i)).isoformat()[5:], **stats(c, sid, (D.fromisoformat(t) - dt.timedelta(days=i)).isoformat())} for i in range(6, -1, -1)]
    left = (D.fromisoformat(shop["plan_until"]) - D.fromisoformat(t)).days
    prods = rows(c, "SELECT id,name,category,buy,sell,qty,minq FROM products WHERE shop_id=? AND archived=0 ORDER BY name COLLATE NOCASE", (sid,))
    if staff:
        for p in prods:
            p["buy"] = 0
    return {
        "shop": shop["name"], "phone": shop["phone"], "place": shop["place"], "me": pub(u),
        "plan": {"until": shop["plan_until"], "days": left, "active": left >= 0, "info": os.environ.get("PAY_INFO", "")},
        "today": {**stats(c, sid, t), "date": t}, "week": week, "products": prods,
        "sales": rows(c, "SELECT id,date,pname,qty,price,customer,receipt_id FROM sales WHERE shop_id=? AND voided=0 ORDER BY id DESC LIMIT 40", (sid,)),
        "expenses": [] if staff else rows(c, "SELECT * FROM expenses WHERE shop_id=? ORDER BY date DESC,id DESC LIMIT 60", (sid,)),
        "debts": [] if staff else rows(c, "SELECT * FROM debts WHERE shop_id=? ORDER BY (amount-paid<=0),date DESC,id DESC", (sid,)),
        "staff": rows(c, "SELECT id,name,email FROM users WHERE shop_id=? AND role='staff'", (sid,)) if u["role"] == "manager" else [],
    }


def report(c, sid, a, z):
    a, z = dstr(a, today()), dstr(z, today())
    if a > z:
        a, z = z, a
    if (D.fromisoformat(z) - D.fromisoformat(a)).days > 366:
        raise ValueError("Choose a period of one year or less")
    P = (sid, a, z)
    days = rows(c, "SELECT date,SUM(qty*price) rev,SUM(qty*cost) cogs FROM sales WHERE shop_id=? AND voided=0 AND date BETWEEN ? AND ? GROUP BY date ORDER BY date", P)
    rev, cogs = sum(x["rev"] for x in days), sum(x["cogs"] for x in days)
    exp = rows(c, "SELECT cat,SUM(amount) amt FROM expenses WHERE shop_id=? AND date BETWEEN ? AND ? GROUP BY cat ORDER BY amt DESC", P)
    te = sum(x["amt"] for x in exp)
    q = lambda sql, a=P: c.execute(sql, a).fetchone()[0]
    return {
        "month": a if a == z else f"{a} → {z}", "revenue": round(rev, 2), "cogs": round(cogs, 2), "gross": round(rev - cogs, 2), "expenses": te, "net": round(rev - cogs - te, 2),
        "bought": q("SELECT COALESCE(SUM(qty*cost),0) FROM purchases WHERE shop_id=? AND date BETWEEN ? AND ?"), "days": days, "exp": exp,
        "top": rows(c, "SELECT pname,SUM(qty) q,SUM(qty*price) rev,SUM(qty*(price-cost)) profit FROM sales WHERE shop_id=? AND voided=0 AND date BETWEEN ? AND ? GROUP BY pname ORDER BY profit DESC LIMIT 8", P),
        "sales": rows(c, "SELECT r.id,r.no,r.date,r.customer,SUM(s.qty*s.price) total FROM receipts r JOIN sales s ON s.receipt_id=r.id AND s.voided=0 WHERE r.shop_id=? AND r.date BETWEEN ? AND ? GROUP BY r.id ORDER BY r.id DESC LIMIT 300", P),
        "dead": rows(c, "SELECT name,qty FROM products WHERE shop_id=? AND archived=0 AND qty>0 AND id NOT IN (SELECT pid FROM sales WHERE shop_id=? AND voided=0 AND date BETWEEN ? AND ?) ORDER BY qty*buy DESC LIMIT 8", (sid, sid, a, z)),
        "owed": q("SELECT COALESCE(SUM(amount-paid),0) FROM debts WHERE shop_id=? AND kind='owed'", (sid,)), "owe": q("SELECT COALESCE(SUM(amount-paid),0) FROM debts WHERE shop_id=? AND kind='owe'", (sid,)),
        "stock_value": round(q("SELECT COALESCE(SUM(qty*buy),0) FROM products WHERE shop_id=? AND archived=0", (sid,)), 2),
    }


def csv_report(c, sid, a, z):
    a, z = dstr(a, today()), dstr(z, today())
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["Receipt", "Date", "Customer", "Product", "Qty", "Price", "Total", "Profit"])
    safe = lambda v: ("'" + v) if isinstance(v, str) and v[:1] in "=+-@" else v
    for r in c.execute("SELECT r.no,s.date,s.customer,s.pname,s.qty,s.price,s.cost FROM sales s LEFT JOIN receipts r ON r.id=s.receipt_id WHERE s.shop_id=? AND s.voided=0 AND s.date BETWEEN ? AND ? ORDER BY s.id", (sid, a, z)):
        w.writerow([r[0], r[1], safe(r[2]), safe(r[3]), r[4], r[5], round(r[4] * r[5], 2), round(r[4] * (r[5] - r[6]), 2)])
    return out.getvalue().encode()


def receipt(c, shop, rid):
    r = c.execute("SELECT * FROM receipts WHERE id=? AND shop_id=?", (rid, shop["id"])).fetchone()
    if not r:
        raise ValueError("Receipt not found")
    items = rows(c, "SELECT pname,qty,price FROM sales WHERE receipt_id=? AND voided=0", (r["id"],))
    return {"shop": shop["name"], "phone": shop["phone"], "place": shop["place"], "no": r["no"], "date": r["date"], "customer": r["customer"],
            "credit": r["credit"], "cashier": r["cashier"], "items": items, "total": round(sum(i["qty"] * i["price"] for i in items), 2)}


def export(c, sid):
    t = lambda n: rows(c, f"SELECT * FROM {n} WHERE shop_id=?", (sid,))
    return json.dumps({n: t(n) for n in ("products", "receipts", "sales", "purchases", "expenses", "debts")}, indent=1).encode()


def act(c, u, shop, name, b):
    sid, uid, role, t = shop["id"], u["id"], u["role"], today()
    if role == "staff" and name != "sale":
        raise ValueError("Your account is not allowed to do that")
    if shop["plan_until"] < t:
        raise ValueError("Subscription expired. You can still view and download your data. Contact ShopPilot to renew.")
    own = lambda tbl, i: c.execute(f"SELECT * FROM {tbl} WHERE id=? AND shop_id=?", (int(i), sid)).fetchone() or (_ for _ in ()).throw(ValueError("Record not found"))
    if name == "product_save":
        v = (clean(b.get("name"), 80, True, "Product name"), clean(b.get("category"), 40), num(b.get("buy"), "Buying price"), num(b.get("sell"), "Selling price"),
             num(b.get("qty"), "Quantity", 0, 1e7), num(b.get("minq"), "Low-stock level", 0, 1e7))
        if b.get("id"):
            old = own("products", b["id"])
            c.execute("UPDATE products SET name=?,category=?,buy=?,sell=?,qty=?,minq=? WHERE id=?", v + (old["id"],))
            if abs(old["qty"] - v[4]) > 1e-9:
                audit(c, sid, uid, "stock_adjust", {"product": old["name"], "from": old["qty"], "to": v[4]})
        else:
            pid = c.execute("INSERT INTO products(shop_id,name,category,buy,sell,qty,minq) VALUES(?,?,?,?,?,?,?)", (sid,) + v).lastrowid
            if v[4] > 0:
                c.execute("INSERT INTO purchases(shop_id,date,pid,pname,qty,cost,supplier) VALUES(?,?,?,?,?,?,?)", (sid, t, pid, v[0], v[4], v[2], "Opening stock"))
    elif name == "product_delete":
        p = own("products", b.get("id"))
        c.execute("UPDATE products SET archived=1 WHERE id=?", (p["id"],))
        audit(c, sid, uid, "product_removed", p["name"])
    elif name == "restock":
        p = own("products", b.get("id"))
        q, cost, sup = num(b.get("qty"), "Quantity", 0.001, 1e7), num(b.get("cost"), "Unit cost"), clean(b.get("supplier"), 60)
        c.execute("UPDATE products SET qty=qty+?,buy=? WHERE id=?", (q, cost, p["id"]))
        c.execute("INSERT INTO purchases(shop_id,date,pid,pname,qty,cost,supplier) VALUES(?,?,?,?,?,?,?)", (sid, t, p["id"], p["name"], q, cost, sup))
        if b.get("credit") and sup:
            c.execute("INSERT INTO debts(shop_id,date,party,kind,amount,note) VALUES(?,?,?,?,?,?)", (sid, t, sup, "owe", round(q * cost, 2), "Stock: " + p["name"]))
    elif name == "sale":
        items = b.get("items") or []
        if not isinstance(items, list) or not items or len(items) > 100:
            raise ValueError("Cart is empty")
        cust, credit = clean(b.get("customer"), 60), bool(b.get("credit"))
        if credit and not cust:
            raise ValueError("Enter the customer name for a credit sale")
        no = c.execute("SELECT COALESCE(MAX(no),0)+1 FROM receipts WHERE shop_id=?", (sid,)).fetchone()[0]
        rid = c.execute("INSERT INTO receipts(shop_id,no,date,ts,customer,credit,cashier) VALUES(?,?,?,?,?,?,?)", (sid, no, t, now(), cust, int(credit), u["name"])).lastrowid
        total = 0.0
        for it in items:
            p = c.execute("SELECT * FROM products WHERE id=? AND shop_id=? AND archived=0", (int(it.get("pid", 0)), sid)).fetchone()
            if not p:
                raise ValueError("Product not found")
            q, pr = num(it.get("qty"), "Quantity", 0.001, 1e6), num(it.get("price"), "Price", 0, 1e9)
            if q > p["qty"] + 1e-9:
                raise ValueError(f"Only {p['qty']:g} of {p['name']} in stock")
            c.execute("UPDATE products SET qty=qty-? WHERE id=?", (q, p["id"]))
            c.execute("INSERT INTO sales(shop_id,receipt_id,date,pid,pname,qty,price,cost,customer) VALUES(?,?,?,?,?,?,?,?,?)", (sid, rid, t, p["id"], p["name"], q, pr, p["buy"], cust))
            total += q * pr
        total = round(total, 2)
        if credit:
            c.execute("INSERT INTO debts(shop_id,date,party,kind,amount,note) VALUES(?,?,?,?,?,?)", (sid, t, cust, "owed", total, f"Credit sale #{no}"))
        audit(c, sid, uid, "sale", {"receipt": no, "total": total})
        return {"receipt": rid, "no": no, "total": total}
    elif name == "sale_delete":  # void, never erase
        s = own("sales", b.get("id"))
        if s["voided"]:
            raise ValueError("Already voided")
        c.execute("UPDATE sales SET voided=1 WHERE id=?", (s["id"],))
        c.execute("UPDATE products SET qty=qty+? WHERE id=? AND shop_id=?", (s["qty"], s["pid"], sid))
        r = c.execute("SELECT * FROM receipts WHERE id=?", (s["receipt_id"],)).fetchone()
        if r and r["credit"]:
            c.execute("UPDATE debts SET amount=MAX(paid,amount-?) WHERE shop_id=? AND note=?", (round(s["qty"] * s["price"], 2), sid, f"Credit sale #{r['no']}"))
        audit(c, sid, uid, "sale_voided", {"sale": s["id"], "item": s["pname"], "qty": s["qty"]})
    elif name == "expense_add":
        c.execute("INSERT INTO expenses(shop_id,date,cat,note,amount) VALUES(?,?,?,?,?)", (sid, dstr(b.get("date"), t), clean(b.get("cat"), 30) or "Other", clean(b.get("note"), 120), num(b.get("amount"), "Amount")))
    elif name == "expense_delete":
        e = own("expenses", b.get("id"))
        c.execute("DELETE FROM expenses WHERE id=?", (e["id"],))
        audit(c, sid, uid, "expense_deleted", dict(e))
    elif name == "debt_add":
        kind = b.get("kind") if b.get("kind") in ("owed", "owe") else "owed"
        c.execute("INSERT INTO debts(shop_id,date,party,kind,amount,note) VALUES(?,?,?,?,?,?)", (sid, t, clean(b.get("party"), 60, True, "Name"), kind, num(b.get("amount"), "Amount", 0.01), clean(b.get("note"), 120)))
    elif name == "debt_pay":
        d = own("debts", b.get("id"))
        a = min(num(b.get("amount"), "Amount", 0.01), d["amount"] - d["paid"])
        c.execute("UPDATE debts SET paid=paid+? WHERE id=?", (a, d["id"]))
        audit(c, sid, uid, "debt_payment", {"party": d["party"], "amount": a})
    elif name == "debt_delete":
        d = own("debts", b.get("id"))
        c.execute("DELETE FROM debts WHERE id=?", (d["id"],))
        audit(c, sid, uid, "debt_deleted", dict(d))
    elif name == "shop":
        c.execute("UPDATE shops SET name=?,phone=?,place=? WHERE id=?", (clean(b.get("name"), 60, True, "Shop name"), clean(b.get("phone"), 30), clean(b.get("place"), 80), sid))
    elif name == "staff_add":
        em, pw = email(b.get("email")), str(b.get("password") or "")
        pwrule(pw)
        if c.execute("SELECT 1 FROM users WHERE email=?", (em,)).fetchone():
            raise ValueError("That email is already registered")
        s, h = mkpw(pw)
        c.execute("INSERT INTO users(email,name,salt,pw,role,shop_id,created) VALUES(?,?,?,?,'staff',?,?)", (em, clean(b.get("name"), 60, True, "Name"), s, h, sid, now()))
    elif name == "staff_remove":
        c.execute("DELETE FROM users WHERE id=? AND shop_id=? AND role='staff'", (int(b.get("id", 0)), sid))
    else:
        raise ValueError("Unknown action")
    return {"ok": True}


# ---------- owner console ----------
def owner_data(c):
    t = today()
    d30 = (D.fromisoformat(t) - dt.timedelta(days=30)).isoformat()
    shops = rows(c, """SELECT s.id,s.name,s.plan_until,s.created,
      (SELECT id FROM users WHERE shop_id=s.id AND role='manager' LIMIT 1) uid,(SELECT email FROM users WHERE shop_id=s.id AND role='manager' LIMIT 1) email,
      (SELECT disabled FROM users WHERE shop_id=s.id AND role='manager' LIMIT 1) disabled,
      (SELECT COALESCE(SUM(qty*price),0) FROM sales WHERE shop_id=s.id AND voided=0 AND date>=?) sales30,
      (SELECT COALESCE(SUM(qty*price),0) FROM sales WHERE shop_id=s.id AND voided=0) sales_all,
      (SELECT MAX(date) FROM sales WHERE shop_id=s.id AND voided=0) last_sale,(SELECT COUNT(*) FROM payments WHERE shop_id=s.id) paid_n
      FROM shops s ORDER BY s.id DESC""", (d30,))
    sm = {r["date"]: r["v"] for r in c.execute("SELECT date,SUM(qty*price) v FROM sales WHERE voided=0 AND date>=? GROUP BY date", ((D.fromisoformat(t) - dt.timedelta(days=13)).isoformat(),))}
    days = [{"d": (D.fromisoformat(t) - dt.timedelta(days=i)).isoformat()[5:], "v": sm.get((D.fromisoformat(t) - dt.timedelta(days=i)).isoformat(), 0)} for i in range(13, -1, -1)]
    weeks = []
    for i in range(7, -1, -1):
        a = (D.fromisoformat(t) - dt.timedelta(days=7 * i + 6)).isoformat()
        z = (D.fromisoformat(t) - dt.timedelta(days=7 * i - 1)).isoformat()
        weeks.append({"n": sum(1 for s in shops if a <= s["created"][:10] < z)})
    one = lambda q, a=(): c.execute(q, a).fetchone()[0]
    bks = sorted(glob.glob(os.path.join(BK, "shoppilot-*.db")), reverse=True)[:10]
    return {"shops": shops, "users": one("SELECT COUNT(*) FROM users WHERE role!='owner'"), "active": sum(1 for s in shops if s["plan_until"] >= t),
            "expired": sum(1 for s in shops if s["plan_until"] < t), "new30": sum(1 for s in shops if s["created"][:10] >= d30), "days": days, "weeks": weeks,
            "sales30": sum(s["sales30"] for s in shops), "pay30": one("SELECT COALESCE(SUM(amount),0) FROM payments WHERE date>=?", (d30,)),
            "pay_all": one("SELECT COALESCE(SUM(amount),0) FROM payments"), "today": t,
            "backups": [{"name": os.path.basename(f), "kb": os.path.getsize(f) // 1024} for f in bks]}


def owner_act(c, u, b):
    a = b.get("act")
    if a == "extend":
        s = c.execute("SELECT * FROM shops WHERE id=?", (int(b.get("shop_id", 0)),)).fetchone()
        if not s:
            raise ValueError("Shop not found")
        days, amt = int(num(b.get("days"), "Days", 1, 3660)), num(b.get("amount"), "Amount", 0, 1e8)
        new = (D.fromisoformat(max(s["plan_until"], today())) + dt.timedelta(days=days)).isoformat()
        c.execute("UPDATE shops SET plan_until=? WHERE id=?", (new, s["id"]))
        c.execute("INSERT INTO payments(shop_id,date,amount,ref,days) VALUES(?,?,?,?,?)", (s["id"], today(), amt, clean(b.get("ref"), 60), days))
        audit(c, s["id"], u["id"], "plan_extended", {"days": days, "amount": amt})
        return {"until": new}
    t = c.execute("SELECT * FROM users WHERE id=? AND role!='owner'", (int(b.get("user_id", 0)),)).fetchone()
    if not t:
        raise ValueError("User not found")
    if a == "disable":
        c.execute("UPDATE users SET disabled=? WHERE id=?", (1 if b.get("disabled") else 0, t["id"]))
        c.execute("DELETE FROM sessions WHERE user_id=?", (t["id"],))
        return {"ok": True}
    if a == "reset_pw":
        temp = secrets.token_urlsafe(9)
        s, h = mkpw(temp)
        c.execute("UPDATE users SET salt=?,pw=?,fails=0,locked_until=0 WHERE id=?", (s, h, t["id"]))
        c.execute("DELETE FROM sessions WHERE user_id=?", (t["id"],))
        audit(c, t["shop_id"], u["id"], "password_reset", t["email"])
        return {"temp": temp}
    raise ValueError("Unknown action")


# ---------- backups ----------
def backup():
    fn = os.path.join(BK, "shoppilot-" + utc().strftime("%Y%m%d-%H%M%S") + ".db")
    src, dst = db(), sqlite3.connect(fn)
    with dst:
        src.backup(dst)
    ok = dst.execute("PRAGMA integrity_check").fetchone()[0]
    dst.close()
    src.close()
    if ok != "ok":
        os.rename(fn, fn + ".CORRUPT")
        raise RuntimeError("Backup failed integrity check")
    for f in sorted(glob.glob(os.path.join(BK, "shoppilot-*.db")))[:-KEEP]:
        os.remove(f)
    return fn


def maintenance():
    while True:
        try:
            backup()
            with tx() as c:
                c.execute("DELETE FROM sessions WHERE expires<?", (int(time.time()),))
        except Exception as e:
            print("Maintenance error:", e, file=sys.stderr)
        time.sleep(BACKUP_HOURS * 3600)


# ---------- HTTP ----------
INDEX = open(os.path.join(HERE, "index.html"), "rb").read()
CSP = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'"


class H(BaseHTTPRequestHandler):
    server_version = "ShopPilot"

    def ip(self):
        return (self.headers.get("X-Forwarded-For") or self.client_address[0]).split(",")[0].strip()

    def secure(self):
        return self.headers.get("X-Forwarded-Proto") == "https" or os.environ.get("SECURE_COOKIES") == "1"

    def cookie(self, tok, clear=False):
        return f"sp_session={tok}; Path=/; HttpOnly; SameSite=Lax; Max-Age={0 if clear else SESSION_DAYS * 86400}" + ("; Secure" if self.secure() else "")

    def send(self, code, body, ct="application/json", hdr=None):
        b = body if isinstance(body, bytes) else (body if isinstance(body, str) else json.dumps(body)).encode()
        self.send_response(code)
        self.send_header("Content-Type", ct + ("; charset=utf-8" if ct.startswith("text") or ct == "application/json" else ""))
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Content-Security-Policy", CSP)
        if self.secure():
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        for k, v in (hdr or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def handle_any(self, method):
        u = urlparse(self.path)
        try:
            if u.path == "/":
                return self.send(200, INDEX, "text/html")
            if u.path == "/healthz":
                return self.send(200, {"ok": True})
            if not u.path.startswith("/api/"):
                return self.send(404, {"error": "Not found"})
            b = {}
            if method == "POST":
                o = self.headers.get("Origin")
                if (o and urlparse(o).netloc != self.headers.get("Host")) or self.headers.get("X-Requested-With") != "ShopPilot":
                    return self.send(403, {"error": "Blocked request"})
                n = int(self.headers.get("Content-Length") or 0)
                if n > 1_000_000:
                    return self.send(413, {"error": "Request too large"})
                b = json.loads(self.rfile.read(n) or b"{}")
                if not isinstance(b, dict):
                    raise ValueError("Bad request")
            res = self.route(method, u.path[5:], b, parse_qs(u.query))
            self.send(*res)
        except ValueError as e:
            self.send(400, {"error": str(e) or "Invalid request"})
        except sqlite3.IntegrityError:
            self.send(400, {"error": "That change was rejected by the data safety checks (for example, stock cannot go below zero)."})
        except (KeyError, TypeError, json.JSONDecodeError):
            self.send(400, {"error": "Invalid request"})
        except (BrokenPipeError, ConnectionResetError):
            pass  # client went away
        except Exception:
            traceback.print_exc()
            try:
                self.send(500, {"error": "Server error. Please try again."})
            except (BrokenPipeError, ConnectionResetError):
                pass

    def route(self, m, name, b, q):
        ck = SimpleCookie(self.headers.get("Cookie", ""))
        tok = ck["sp_session"].value if "sp_session" in ck else ""
        ok = lambda o: (200, o, "application/json", None)
        with tx() as c:
            if m == "POST" and name == "register":
                u, t = register(c, b, self.ip())
                return 200, {"user": pub(u)}, "application/json", {"Set-Cookie": self.cookie(t)}
            if m == "POST" and name == "login":
                u, t, err = login(c, b, self.ip())
                return (401, {"error": err}, "application/json", None) if err else (200, {"user": pub(u)}, "application/json", {"Set-Cookie": self.cookie(t)})
            u = user_from(c, tok)
            if name == "me":
                return ok({"user": pub(u) if u else None})
            if not u:
                return 401, {"error": "Please log in"}, "application/json", None
            if name == "logout":
                c.execute("DELETE FROM sessions WHERE h=?", (sha(tok),))
                return 200, {"ok": True}, "application/json", {"Set-Cookie": self.cookie("", True)}
            if name == "password" and m == "POST":
                cur = c.execute("SELECT * FROM users WHERE id=?", (u["id"],)).fetchone()
                if not hmac.compare_digest(hp(str(b.get("current") or ""), cur["salt"]), cur["pw"]):
                    raise ValueError("Current password is wrong")
                new = str(b.get("new") or "")
                pwrule(new)
                s, h = mkpw(new)
                c.execute("UPDATE users SET salt=?,pw=? WHERE id=?", (s, h, u["id"]))
                c.execute("DELETE FROM sessions WHERE user_id=? AND h!=?", (u["id"], sha(tok)))
                return ok({"ok": True})
            if u["role"] == "owner":
                if name == "owner" and m == "GET":
                    return ok(owner_data(c))
                if name == "owner" and m == "POST" and b.get("act") != "backup":
                    return ok(owner_act(c, u, b))
                if not (name == "owner" and m == "POST") and name != "owner/backup.db":
                    raise ValueError("Not available for the owner account")
            else:
                shop = c.execute("SELECT * FROM shops WHERE id=?", (u["shop_id"],)).fetchone()
                if m == "POST":
                    return ok(act(c, u, shop, name, b))
                if name == "data":
                    return ok(data(c, u, shop))
                if u["role"] == "staff":
                    raise ValueError("Not allowed")
                f, z = q.get("from", [today()])[0], q.get("to", [today()])[0]
                if name == "report":
                    return ok(report(c, shop["id"], f, z))
                if name == "report.csv":
                    return 200, csv_report(c, shop["id"], f, z), "text/csv", {"Content-Disposition": "attachment; filename=shoppilot-report.csv"}
                if name == "receipt":
                    return ok(receipt(c, shop, int(q.get("id", ["0"])[0])))
                if name == "export":
                    return 200, export(c, shop["id"]), "application/json", {"Content-Disposition": "attachment; filename=my-shop-data.json"}
                raise ValueError("Unknown request")
        # owner backup (outside the transaction so the file copy is not blocked)
        fn = backup()
        if name == "owner/backup.db":
            return 200, open(fn, "rb").read(), "application/octet-stream", {"Content-Disposition": "attachment; filename=" + os.path.basename(fn)}
        return ok({"file": os.path.basename(fn)})

    def do_GET(self):
        self.handle_any("GET")

    def do_POST(self):
        self.handle_any("POST")

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    init()
    ensure_owner()
    threading.Thread(target=maintenance, daemon=True).start()
    port = int(os.environ.get("PORT", 8000))
    host = "0.0.0.0" if ("--lan" in sys.argv or os.environ.get("PORT")) else "127.0.0.1"
    print(f"\n  ShopPilot Cloud running -> http://{'127.0.0.1' if host.startswith('127') else host}:{port}\n  Data folder: {DATA}\n")
    ThreadingHTTPServer((host, port), H).serve_forever()
