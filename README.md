# TEVA password and SSH-key setup

Three commands, run **in this order**, for the appliances listed in `inventory.csv`:

| Step | Command | What it does |
|---|---|---|
| 1 | `change_password.py` | Changes the web-UI password from `TE_DEFAULT_PASSWORD` to `TE_UI_PASSWORD`. |
| 2 | `load_keys.py` | Uploads your SSH public key through the web UI. |
| 3 | `verify_ssh.py` | Logs in with your SSH key and shows each appliance's hostname and IP addresses. Changes nothing. |

Always run step 2 **after** step 1: changing the web-UI password can remove SSH keys that were already uploaded.

## Install

Install [uv](https://docs.astral.sh/uv/getting-started/installation/), then run the commands below from this folder. Open a new terminal if `uv` is not found after installing it.

```sh
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh
uv sync --locked
cp -n .env.example .env
cp -n inventory.example.csv inventory.csv
```

```powershell
# Windows (PowerShell)
winget install --id=astral-sh.uv -e
uv sync --locked
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
if (-not (Test-Path inventory.csv)) { Copy-Item inventory.example.csv inventory.csv }
```

## Configure

**`inventory.csv`**: copy `inventory.example.csv` as shown above, then replace the example
addresses with each appliance's current IP. The working inventory is kept out of Git.
Use one appliance per line. Lines starting with `#` are ignored.

```csv
hostname,ip_address
TE1,192.0.2.10
TE2,192.0.2.11
```

**`.env`**: fill in your values. Keep this file private.

```dotenv
TE_UI_USERNAME=admin
TE_DEFAULT_PASSWORD='initial-web-ui-password'
TE_UI_PASSWORD='new-web-ui-password'
TE_SSH_USERNAME=thousandeyes
TE_SSH_PUBLIC_KEY_PATHS=~/.ssh/teva_ed25519.pub
TE_SSH_PRIVATE_KEY=~/.ssh/teva_ed25519
TE_SSH_PRIVATE_KEY_PASSPHRASE=
TE_SSH_KNOWN_HOSTS=~/.ssh/known_hosts
```

- `TE_DEFAULT_PASSWORD` is the appliance's **initial** password, used only to sign in the first time. `TE_UI_PASSWORD` is the password the appliance uses **after** step 1. Do not edit `.env` between the steps.
- Put passwords in **single quotes**. They are used exactly as written; the tools stop with a message if a value could be misread.
- Windows paths work without quotes, for example `C:\Users\you\.ssh\teva_ed25519.pub`. `~` also works on Windows.
- Leave `TE_SSH_PRIVATE_KEY_PASSPHRASE` empty for an unencrypted key, or to type the passphrase when asked.

**Without `.env`**: any setting that is missing from `.env` is read from an environment variable with the same name. If a setting appears in both places, `.env` wins.

```sh
export TE_UI_PASSWORD='new-web-ui-password'        # macOS / Linux
```
```powershell
$env:TE_UI_PASSWORD = 'new-web-ui-password'        # PowerShell
```
```bat
set "TE_UI_PASSWORD=new-web-ui-password"           &REM Command Prompt
```

## Run

Start with one appliance. Use `uv run python` on macOS and Linux, and on Windows too.

```sh
uv run python change_password.py --only TE1            # checks settings only; contacts nothing
uv run python change_password.py --only TE1 --apply    # changes the password
uv run python load_keys.py --only TE1
uv run python verify_ssh.py --only TE1
```

Before step 3, add each appliance's SSH host key to `known_hosts` once: run `ssh thousandeyes@<ip>` (add `-p PORT` if you set `TE_SSH_PORT`) and compare the fingerprint with the one on the appliance console before you accept it. If a host key is missing, `verify_ssh.py` prints the exact command to use.

Leave out `--only TE1` to process the whole inventory. Steps 1 and 2 then handle one appliance at a time and wait for you to type `Y` before starting the next one. `--parallel` runs several at once. For steps 1 and 2, the first appliance runs alone and the rest start only if it succeeds (appliances that were already done don't count as a test).

Other options: `--only NAME` (repeatable), `--inventory PATH`, `--env-file PATH`, `--timeout SECONDS` (default 15). `change_password.py --check-login --only TE1` shows which password an appliance currently accepts, without changing anything.

## Safety built in

These tools drive the same web pages you would use in a browser, and they are deliberately gentle:

- Before sending a password, they check that the web UI answers normally. On any server error (HTTP 5xx), timeout, or unexpected answer, they stop working on that appliance immediately. They never retry.
- They send at most two failed logins per appliance in 15 minutes, which stays below the appliance's login lockout. After a server error, a timeout, or a lockout they leave that appliance alone for a while, even when you rerun from another terminal. The message tells you when it is safe to try again.
- Ctrl+C stops all traffic: nothing new is sent after it. If a password or key change was already on its way, the message tells you how to check the result.
- Rerunning is safe. Appliances that are already done are detected and reported as `ok`, and no change is sent to them again.
- Passwords, passphrases, and private keys are never printed or logged.

## Results

Each run prints a summary and saves a log in `logs/` and a CSV report in `reports/`. Exit code `0` means every selected appliance succeeded, `1` means at least one failed, `2` means nothing was contacted because of a settings problem, and `130` means you pressed Ctrl+C.

| Message says | What to do |
|---|---|
| `web-UI service behind it is not running (HTTP 502)` | The appliance is starting or its web UI is unhealthy. Wait, open `https://<ip>` in a browser, and rerun once it loads. Restart the appliance if the page does not load after about 10 minutes. |
| `no answer from ... on port 443` / `refused` | Wrong IP address, appliance off, or network/VPN problem. |
| `rejected TE_DEFAULT_PASSWORD and TE_UI_PASSWORD` | Neither password works. Sign in with a browser to find the right one, then correct `.env`. |
| `not contacted: ... waits until HH:MM UTC` | A recent failure protects the appliance. Wait until the time shown. |
| `requires its initial web-UI password change` | Run `change_password.py` for that appliance first. |
| `rejected the SSH key` | Run `load_keys.py` again for that appliance. |
| `is not in ...known_hosts` / `host key ... differs` | Add or update the host key as described in Run. |
| `terminal cannot answer the Y/N pause` | Use PowerShell, Command Prompt, or Terminal (Git Bash needs `winpty`), or add `--only NAME`. |
