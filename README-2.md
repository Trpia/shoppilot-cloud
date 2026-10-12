# ShopPilot Cloud

Files: `app.py` (server + database), `index.html` (the app screen), `Dockerfile`, `test_app.py`.
No packages to install. Needs Python 3.8+.

## Run on your computer
    OWNER_EMAIL=you@example.com OWNER_PASSWORD='choose-a-long-password' python app.py
Open http://127.0.0.1:8000 and log in with those details. They are used only the first time the
database is created. If you leave them out, a random owner password is printed in the console.
Never put the password in the code or in GitHub.

## Host it (needs a disk that survives restarts, because the database is a file)
- Render / Railway / Fly.io: deploy from your GitHub repo using the Dockerfile and attach a
  persistent volume mounted at `/data`.
- Any cheap VPS: `python app.py` behind Caddy or nginx for HTTPS.
Free hosts that wipe the disk on restart will lose data, so avoid them for real clients.
Always serve over HTTPS.

## Settings (environment variables)
OWNER_EMAIL, OWNER_PASSWORD (first start), PORT, DATA_DIR (default ./data), ALLOW_REGISTER (1 or 0),
PAY_INFO (text shown to shops, e.g. "Pay KSh 500 to M-Pesa Till 123456 and send the code"),
BACKUP_HOURS (default 6), KEEP_BACKUPS (default 28), TZ_HOURS (default 3 for Kenya).

## Getting paid
New shops get 14 days free. When a shop pays you by M-Pesa, open Owner console > Shops >
"Record payment" and enter the amount and M-Pesa code. That adds days to their plan. Expired
shops can still view and download their data but cannot add records.

## Test
    python test_app.py
