# Suricata Dashboard — Cloudflare Tunnel Setup & Operations Guide

This document describes how to expose the Streamlit Suricata dashboard
(`suri_dashboard.py`) running on this VM to the public internet via a
Cloudflare Tunnel, secured with Cloudflare Access, using the domain
`yokedostrich.com` (registered at GoDaddy).

The result:

```
browser → https://your-dashboard.example.com → Cloudflare edge (TLS + Access auth)
   → (outbound encrypted tunnel) cloudflared on this VM
   → Streamlit on 127.0.0.1:8765
```

Key properties of this design:

- **No inbound ports** are opened on the Palo Alto firewall. `cloudflared`
  makes an *outbound* HTTPS connection to Cloudflare; the PA only sees
  normal outbound web traffic.
- **TLS is automatic** — Cloudflare terminates it at the edge and renews the
  certificate. No Let's Encrypt juggling.
- **Authentication** is provided by Cloudflare Access (email allow-list),
  because Streamlit has no built-in auth. Without Access, the dashboard
  would be public.
- **Cost: $0** (Tunnel + Access are free for up to 50 users).

---

## Architecture summary

| Component              | Status                                               |
| ---------------------- | ---------------------------------------------------- |
| DNS for yokedostrich.com | Managed by Cloudflare (GoDaddy = registrar only)   |
| TLS certificate        | Automatic via Cloudflare edge                        |
| Public hostname        | https://your-dashboard.example.com                        |
| Auth                   | Cloudflare Access (email allow-list)                 |
| Tunnel                 | `cloudflared` systemd service, outbound only         |
| Streamlit              | systemd service, bound to 127.0.0.1:8765             |
| Palo Alto firewall      | No inbound rule needed (tunnel is outbound HTTPS)    |
| Cost                   | $0                                                   |

---

## Prerequisites

- The Streamlit dashboard (`/home/suricata/suri_dashboard.py`) runs on this
  VM and is reachable locally on port 8765.
- The DuckDB ingester (`eve_tail2duckdb.py`) is running and populating
  `/home/suricata/eve.duckdb`.
- You own `yokedostrich.com` (GoDaddy) and have access to its DNS/nameserver
  settings at GoDaddy.
- You have sudo on this VM (needed to install `cloudflared` and register
  systemd services).
- You manage the Palo Alto firewall (only relevant to confirm *no* inbound
  rule is required — the tunnel is outbound).

---

## Step 1 — Create a Cloudflare account

1. Go to https://dash.cloudflare.com/sign-up.
2. Enter your email and a password.
3. Verify the email Cloudflare sends you.

---

## Step 2 — Add `yokedostrich.com` to Cloudflare

1. Log in to https://dash.cloudflare.com.
2. Click **+ Add a site**.
3. Enter `yokedostrich.com` and click Continue.
4. On the plan page, select **Free**.
5. Cloudflare scans your current DNS records. **Review them carefully** and
   make sure every existing record (A/CNAME/MX/TXT) is present — especially
   **MX and TXT records if you host email on this domain** (Google
   Workspace, Microsoft 365, etc.). Losing email is the most common
   casualty of a DNS transfer.
6. Click Continue. Cloudflare assigns **two nameservers** that look like:
   ```
   xxx.ns.cloudflare.com
   yyy.ns.cloudflare.com
   ```

---

## Step 3 — Change nameservers at GoDaddy to Cloudflare's

This delegates DNS to Cloudflare. It is reversible.

1. Log in to https://dcc.godaddy.com/manage/yokedostrich.com/dns
   (or GoDaddy → My Products → DNS → Manage Zones → yokedostrich.com).
2. Find the **Nameservers** section. It may say "Default" or "Custom".
3. Switch to **Custom** nameservers and enter the two Cloudflare gave you
   (use the exact hostnames Cloudflare showed, not literally xxx/yyy):
   ```
   ns1 → xxx.ns.cloudflare.com
   ns2 → yyy.ns.cloudflare.com
   ```
4. Save.
5. Back in Cloudflare, click **Done, check nameservers**. Cloudflare polls
   until propagation completes (minutes to a few hours) and emails you when
   the domain is active.

> ⚠️ While propagation is happening, DNS-dependent services on
> yokedostrich.com (email especially) rely on the records you confirmed in
> Step 2. If email is critical, do this during a low-traffic window and
> verify the imported records twice.

You can proceed with Steps 4–6 while DNS propagates — they don't depend on
it being live yet.

---

## Step 4 — Install `cloudflared` on this VM

Run on the VM:

```bash
# Add Cloudflare's apt repo and signing key
sudo mkdir -p --mode=0755 /usr/share/keyrings
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg \
  | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared $(lsb_release -cs) main' \
  | sudo tee /etc/apt/sources.list.d/cloudflared.list

sudo apt-get update
sudo apt-get install -y cloudflared
cloudflared --version
```

---

## Step 5 — Authenticate `cloudflared` with your Cloudflare account

```bash
cloudflared tunnel login
```

- It prints a URL. Open it in a browser, log in to Cloudflare if needed,
  and **select `yokedostrich.com`** from the list of zones.
- Authorize. The terminal shows "You have successfully logged in."
- This saves a cert to `~/.cloudflared/cert.pem` used to create tunnels.
  **Do not delete it.**

---

## Step 6 — Create a tunnel and route Streamlit through it

```bash
cloudflared tunnel create suricata
```

This prints a **tunnel UUID** and a credentials file path:
`~/.cloudflared/<UUID>.json`. Note the UUID. <YOUR-TUNNEL-UUID>

Create the config file (replace `<UUID>` in both places):

```bash
mkdir -p ~/.cloudflared
cat > ~/.cloudflared/config.yml <<'EOF'
tunnel: <YOUR-TUNNEL-UUID>
credentials-file: /home/suricata/.cloudflared/<YOUR-TUNNEL-UUID>.json

ingress:
  - hostname: your-dashboard.example.com
    service: http://localhost:8765
  - service: http_status:404
EOF
```

Create the DNS record that maps the hostname to the tunnel (this adds a
CNAME in Cloudflare DNS automatically — you do not touch GoDaddy again):

```bash
cloudflared tunnel route dns suricata your-dashboard.example.com
```

If it says the record already exists, that's fine — the route is in place.

---

## Step 7 — Test the tunnel manually

Start Streamlit (if not already running as a service):

```bash
export PATH="$HOME/.local/bin:$PATH"
cd /home/suricata
streamlit run suri_dashboard.py --server.address 127.0.0.1 --server.port 8765 \
  --server.headless true --browser.gatherUsageStats false
```

In a **second** terminal, run the tunnel in the foreground:

```bash
cloudflared tunnel run suricata
```

You should see "Registered tunnel connection" (a few of them). Open
**https://your-dashboard.example.com** in a browser — you should see the
dashboard (unauthenticated for now). This confirms the tunnel works.

If the hostname doesn't resolve, DNS may not have propagated yet — wait and
retry. Check with `dig your-dashboard.example.com` (it should be a CNAME to
`<UUID>.cfargotunnel.com`).

Once it works, stop the foreground `cloudflared` with **Ctrl-C** — we'll
install it as a service next.

---

## Step 8 — Add Cloudflare Access (authentication)

Without this, the dashboard is open to the internet with no login.

1. In the Cloudflare dashboard, go to **Zero Trust**
   (https://one.dash.cloudflare.com/). First visit prompts you to set a
   "team name" — pick anything (e.g. `yokedostrich`). Choose the **Free**
   plan.
2. Go to **Access → Applications → Add an application**.
3. Choose **Self-hosted**.
4. Application name: `Suricata Dashboard`.
5. Public domain: add `your-dashboard.example.com`.
6. Click Next. Under **Policy**:
   - Policy name: `Just me` (or whatever).
   - **Action: Allow**.
   - Under **Include** → selector **Emails** → enter **your email**.
   - Save.
7. Save the application.

Now visiting https://your-dashboard.example.com redirects to a Cloudflare login
page. Sign in with the allowed email (Google/GitHub one-time codes both work
on the free tier). Everyone else is denied.

To add more people later: edit the policy and add their emails.
<YOUR_PASSWORD>
/home/suricata/.streamlit/secrets.toml (chmod 600)
---

## Step 9 — Run `cloudflared` as a systemd service

```bash
sudo cloudflared service install
```

Then point the service at your config explicitly (the default install may
look in the wrong place):

```bash
sudo systemctl edit cloudflared.service
```

In the editor, add (replacing `<UUID>` is NOT needed here — just use the
exact config path):

```ini
[Service]
ExecStart=
ExecStart=/usr/bin/cloudflared --config /home/suricata/.cloudflared/config.yml tunnel run suricata
```

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable cloudflared.service
sudo systemctl restart cloudflared.service
sudo systemctl status cloudflared.service
```

You should see `active (running)`. Visit https://your-dashboard.example.com again
— still works, now survives reboots.

---

## Step 10 — Run Streamlit as a systemd service

A unit file has been created at `/home/suricata/streamlit.service`. It
binds Streamlit to **127.0.0.1** (not 0.0.0.0) so only `cloudflared` on the
same VM can reach it — not the LAN, not the public IP.

Install it:

```bash
sudo cp /home/suricata/streamlit.service /etc/systemd/system/streamlit.service
sudo systemctl daemon-reload
sudo systemctl enable streamlit.service
sudo systemctl start streamlit.service
sudo systemctl status streamlit.service
```

You should see `active (running)`. Visit https://your-dashboard.example.com —
the dashboard comes up through the tunnel.

Both `cloudflared` and `streamlit` now start automatically on boot and
restart on crash.

---

## Operating commands

| Task                              | Command                                              |
| --------------------------------- | ---------------------------------------------------- |
| View tunnel logs                  | `journalctl -u cloudflared.service -f`              |
| View Streamlit logs               | `journalctl -u streamlit.service -f`               |
| Restart Streamlit (after editing `suri_dashboard.py`) | `sudo systemctl restart streamlit.service` |
| Restart the tunnel (after editing `~/.cloudflared/config.yml`) | `sudo systemctl restart cloudflared.service` |
| Stop public access temporarily    | `sudo systemctl stop cloudflared`                   |
| Resume public access              | `sudo systemctl start cloudflared`                  |
| Add/remove dashboard users        | Cloudflare dashboard → Zero Trust → Access → Applications → edit policy email list |
| Check tunnel status               | `sudo systemctl status cloudflared.service`         |
| Check Streamlit status            | `sudo systemctl status streamlit.service`           |

---

## Notes & cautions

- **The dashboard has no auth of its own.** Cloudflare Access is the gate.
  Do not bypass it by exposing Streamlit on `0.0.0.0` or opening a PA
  port-forward to 8765, or you lose the auth layer.
- **Suricata alert data can reveal internal IPs/hostnames.** That's fine
  behind Access with just-you, but if you later add users, be mindful they
  can see your internal network details.
- **Email on yokedostrich.com** depends on the MX records imported in
  Step 2. Verify them before the nameserver switch completes (Step 3).

---

## Troubleshooting

| Symptom                                  | Likely cause / fix                                  |
| ---------------------------------------- | --------------------------------------------------- |
| `your-dashboard.example.com` doesn't resolve  | DNS propagation not done. `dig yokedostrich.com NS` should show Cloudflare nameservers. Wait. |
| Hostname resolves but 404 at Cloudflare  | Mismatch between `config.yml` hostname and `tunnel route dns` hostname — they must be identical. |
| 502 Bad Gateway from Cloudflare          | Streamlit isn't running on 127.0.0.1:8765. `sudo systemctl status streamlit.service`. |
| Tunnel service can't find config         | The `systemctl edit` override must point to `/home/suricata/.cloudflared/config.yml` exactly. |
| Access login loop / not let in           | The email you're signing in with isn't in the Access policy allow-list. |
| Dashboard loads but data is stale        | The DuckDB ingester (`eve_tail2duckdb.py`) may have stopped. `ps aux \| grep eve_tail`. |
| Lock errors in dashboard                 | Ingester holding the write lock. Use the ↻ Refresh now button; the dashboard retries for ~60s. |

---

## File locations on this VM

| File                                      | Purpose                              |
| ----------------------------------------- | ------------------------------------ |
| `/home/suricata/suri_dashboard.py`        | The Streamlit dashboard app          |
| `/home/suricata/eve_tail2duckdb.py`       | The eve.json → DuckDB ingester       |
| `/home/suricata/eve.duckdb`               | The DuckDB database                  |
| `/home/suricata/streamlit.service`        | systemd unit for Streamlit (copy to /etc/systemd/system/) |
| `/home/suricata/.cloudflared/config.yml`  | cloudflared tunnel config            |
| `/home/suricata/.cloudflared/<UUID>.json` | cloudflared tunnel credentials       |
| `/home/suricata/.cloudflared/cert.pem`    | cloudflared account cert (from login) |
