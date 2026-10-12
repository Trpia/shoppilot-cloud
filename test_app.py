"""Run: python test_app.py  - starts a temporary server and checks logins, permissions, stock and profit maths."""
import http.client, json, os, subprocess, sys, tempfile, time, datetime

PORT = 8791
tmp = tempfile.mkdtemp()
env = dict(os.environ, PORT=str(PORT), DATA_DIR=tmp, OWNER_EMAIL="boss@test.com", OWNER_PASSWORD="OwnerPass123")
srv = subprocess.Popen([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.py")], env=env, stdout=subprocess.DEVNULL)
time.sleep(1.5)


class S:  # tiny client with a cookie jar
    def __init__(s): s.ck = ""
    def call(s, m, path, body=None):
        c = http.client.HTTPConnection("127.0.0.1", PORT)
        h = {"Cookie": s.ck, "Content-Type": "application/json", "X-Requested-With": "ShopPilot"}
        c.request(m, path, json.dumps(body) if body is not None else None, h)
        r = c.getresponse(); raw = r.read()
        sc = r.getheader("Set-Cookie")
        if sc: s.ck = sc.split(";")[0]
        try: return r.status, json.loads(raw)
        except Exception: return r.status, raw


fails = 0
def check(name, cond):
    global fails
    print(("PASS " if cond else "FAIL ") + name)
    fails += 0 if cond else 1

try:
    a, b, o = S(), S(), S()
    check("weak password rejected", a.call("POST", "/api/register", {"name": "A", "shop": "Shop A", "email": "a@x.com", "password": "G17622"})[0] == 400)
    check("register A", a.call("POST", "/api/register", {"name": "Amina", "shop": "Shop A", "email": "a@x.com", "password": "StrongPass1"})[0] == 200)
    check("register B", b.call("POST", "/api/register", {"name": "Bob", "shop": "Shop B", "email": "b@x.com", "password": "StrongPass2"})[0] == 200)
    check("duplicate email rejected", S().call("POST", "/api/register", {"name": "X", "shop": "X", "email": "A@x.com", "password": "StrongPass1"})[0] == 400)
    a.call("POST", "/api/product_save", {"name": "Lotion", "category": "Skin", "buy": 100, "sell": 150, "qty": 10, "minq": 3})
    a.call("POST", "/api/product_save", {"name": "Gloss", "buy": 40, "sell": 100, "qty": 2, "minq": 3})
    d = a.call("GET", "/api/data")[1]
    lot = [p for p in d["products"] if p["name"] == "Lotion"][0]
    check("two products saved", len(d["products"]) == 2)
    s, r = a.call("POST", "/api/sale", {"items": [{"pid": lot["id"], "qty": 3, "price": 150}]})
    check("sale ok, total 450", s == 200 and r["total"] == 450)
    d = a.call("GET", "/api/data")[1]
    check("stock reduced to 7", [p for p in d["products"] if p["name"] == "Lotion"][0]["qty"] == 7)
    check("overselling blocked", a.call("POST", "/api/sale", {"items": [{"pid": lot["id"], "qty": 8, "price": 150}]})[0] == 400)
    check("failed sale left stock at 7", [p for p in a.call("GET", "/api/data")[1]["products"] if p["name"] == "Lotion"][0]["qty"] == 7)
    check("negative price rejected", a.call("POST", "/api/sale", {"items": [{"pid": lot["id"], "qty": 1, "price": -5}]})[0] == 400)
    a.call("POST", "/api/expense_add", {"cat": "Transport", "amount": 50})
    t = a.call("GET", "/api/data")[1]["today"]
    check("today sales 450, gross 150, net 100", (t["sales"], t["gross"], t["net"]) == (450, 150, 100))
    s, r = a.call("POST", "/api/sale", {"items": [{"pid": lot["id"], "qty": 2, "price": 150}], "customer": "Wanjiku", "credit": True})
    debts = a.call("GET", "/api/data")[1]["debts"]
    check("credit sale created debt of 300", len(debts) == 1 and debts[0]["amount"] == 300)
    sale_row = a.call("GET", "/api/data")[1]["sales"][0]
    a.call("POST", "/api/sale_delete", {"id": sale_row["id"]})
    d = a.call("GET", "/api/data")[1]
    check("void restores stock to 7 and cuts debt to 0", [p for p in d["products"] if p["name"] == "Lotion"][0]["qty"] == 7 and d["debts"][0]["amount"] == 0)
    rep = a.call("GET", "/api/report?from=%s&to=%s" % ((datetime.date.today() - datetime.timedelta(days=2)).isoformat(), (datetime.date.today() + datetime.timedelta(days=2)).isoformat()))[1]
    check("report revenue 450 / gross 150 / net 100", (rep["revenue"], rep["gross"], rep["net"]) == (450, 150, 100))
    check("receipt readable by owner shop", a.call("GET", "/api/receipt?id=%d" % r["receipt"])[0] == 200)
    check("shop B cannot read A's receipt", b.call("GET", "/api/receipt?id=%d" % r["receipt"])[0] == 400)
    check("shop B sees no products", b.call("GET", "/api/data")[1]["products"] == [])
    check("shop B cannot edit A's product", b.call("POST", "/api/product_save", {"id": lot["id"], "name": "Hack", "buy": 1, "sell": 1, "qty": 1, "minq": 1})[0] == 400)
    check("not logged in -> 401", S().call("GET", "/api/data")[0] == 401)
    check("POST without header blocked", http.client.HTTPConnection("127.0.0.1", PORT).request("POST", "/api/login", "{}") is None)
    a.call("POST", "/api/staff_add", {"name": "Cashier", "email": "c@x.com", "password": "StaffPass1"})
    c = S(); check("staff login", c.call("POST", "/api/login", {"email": "c@x.com", "password": "StaffPass1"})[0] == 200)
    sd = c.call("GET", "/api/data")[1]
    check("staff cannot see buying price or profit", sd["products"][0]["buy"] == 0 and sd["week"] == [] and sd["expenses"] == [])
    check("staff cannot add products", c.call("POST", "/api/product_save", {"name": "Z", "buy": 1, "sell": 2, "qty": 1, "minq": 1})[0] == 400)
    check("staff can sell", c.call("POST", "/api/sale", {"items": [{"pid": lot["id"], "qty": 1, "price": 150}]})[0] == 200)
    check("wrong password refused", S().call("POST", "/api/login", {"email": "a@x.com", "password": "nope"})[0] == 401)
    check("owner login", o.call("POST", "/api/login", {"email": "boss@test.com", "password": "OwnerPass123"})[0] == 200)
    od = o.call("GET", "/api/owner")[1]
    check("owner sees 2 shops", len(od["shops"]) == 2)
    check("owner cannot read shop data", o.call("GET", "/api/data")[0] == 400)
    sid = [x for x in od["shops"] if x["name"] == "Shop A"][0]["id"]
    check("owner records payment", o.call("POST", "/api/owner", {"act": "extend", "shop_id": sid, "amount": 500, "ref": "QWE123", "days": 30})[0] == 200)
    check("owner income 500", o.call("GET", "/api/owner")[1]["pay30"] == 500)
    check("owner backup works", o.call("POST", "/api/owner", {"act": "backup"})[0] == 200)
    check("shop user cannot reach owner API", a.call("GET", "/api/owner")[0] == 400)
finally:
    srv.terminate()
print("\n%s" % ("ALL TESTS PASSED" if not fails else f"{fails} TEST(S) FAILED"))
sys.exit(1 if fails else 0)
