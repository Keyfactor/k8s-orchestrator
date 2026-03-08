#!/usr/bin/env python3
"""
Reads integration-manifest.json and regenerates the four store type scripts:
  scripts/store_types/bash/kfutil_create_store_types.sh
  scripts/store_types/bash/curl_create_store_types.sh
  scripts/store_types/powershell/kfutil_create_store_types.ps1
  scripts/store_types/powershell/restmethod_create_store_types.ps1

Run from the repo root:
  python3 scripts/store_types/generate_scripts.py
Or via Make:
  make store-types-gen-scripts
"""

import json
import os
import copy

MANIFEST = "integration-manifest.json"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASH_DIR = os.path.join(SCRIPT_DIR, "bash")
PS_DIR = os.path.join(SCRIPT_DIR, "powershell")


def load_store_types(manifest_path=MANIFEST):
    with open(manifest_path) as f:
        manifest = json.load(f)
    return manifest["about"]["orchestrator"]["store_types"]


def clean_store_type(st):
    """Strip fields not accepted or not needed by the Keyfactor REST API."""
    st = copy.deepcopy(st)
    st.pop("ClientMachineDescription", None)
    # ServerUsername/ServerPassword are server credentials handled by ServerRequired=true.
    # Description is metadata not accepted by the certificatestoretypes endpoint.
    st["Properties"] = [
        {k: v for k, v in p.items() if k != "Description"}
        for p in st.get("Properties", [])
        if p.get("Name") not in ("ServerUsername", "ServerPassword")
    ]
    return st


def store_type_json(st, indent=2):
    return json.dumps(clean_store_type(st), indent=indent)


# ---------------------------------------------------------------------------
# kfutil bash
# ---------------------------------------------------------------------------
KFUTIL_BASH_HEADER = """\
#!/usr/bin/env bash

# Creates all {count} Kubernetes Orchestrator store types using kfutil.
# kfutil reads store type definitions from the Keyfactor integration catalog.
#
# Prerequisites:
#   - kfutil installed: https://github.com/Keyfactor/kfutil#quickstart
#   - Auth environment variables (see README.md for options)
#
# Auto-generated from integration-manifest.json — do not edit by hand.
# Regenerate with: make store-types-gen-scripts

if ! command -v kfutil &> /dev/null; then
    echo "kfutil could not be found. Please install kfutil"
    echo "See the official docs: https://github.com/Keyfactor/kfutil#quickstart"
    exit 1
fi

if [ -z "$KEYFACTOR_HOSTNAME" ]; then
    echo "KEYFACTOR_HOSTNAME not set — launching kfutil login"
    kfutil login
fi

"""

KFUTIL_BASH_FOOTER = '\necho "Done. All store types created."\n'


def gen_kfutil_bash(store_types):
    lines = [KFUTIL_BASH_HEADER.format(count=len(store_types))]
    for st in store_types:
        lines.append(f'kfutil store-types create --name "{st["ShortName"]}"\n')
    lines.append(KFUTIL_BASH_FOOTER)
    return "".join(lines)


# ---------------------------------------------------------------------------
# kfutil PowerShell
# ---------------------------------------------------------------------------
KFUTIL_PS_HEADER = """\
# Creates all {count} Kubernetes Orchestrator store types using kfutil.
# kfutil reads store type definitions from the Keyfactor integration catalog.
#
# Prerequisites:
#   - kfutil installed: https://github.com/Keyfactor/kfutil#quickstart
#   - Auth environment variables (see README.md for options)
#
# Auto-generated from integration-manifest.json — do not edit by hand.
# Regenerate with: make store-types-gen-scripts

# Uncomment if kfutil is not in your PATH
# Set-Alias -Name kfutil -Value 'C:\\Program Files\\Keyfactor\\kfutil\\kfutil.exe'

if ($null -eq (Get-Command "kfutil" -ErrorAction SilentlyContinue)) {{
    Write-Host "kfutil could not be found in your PATH. Please install kfutil"
    Write-Host "See the official docs: https://github.com/Keyfactor/kfutil#quickstart"
    exit 1
}}

if (-not $env:KEYFACTOR_HOSTNAME) {{
    Write-Host "KEYFACTOR_HOSTNAME not set — launching kfutil login"
    & kfutil login
}}

"""

KFUTIL_PS_FOOTER = '\nWrite-Host "Done. All store types created."\n'


def gen_kfutil_ps(store_types):
    lines = [KFUTIL_PS_HEADER.format(count=len(store_types))]
    for st in store_types:
        lines.append(f'& kfutil store-types create --name "{st["ShortName"]}"\n')
    lines.append(KFUTIL_PS_FOOTER)
    return "".join(lines)


# ---------------------------------------------------------------------------
# curl bash
# ---------------------------------------------------------------------------
CURL_BASH_HEADER = """\
#!/usr/bin/env bash

# Creates all {count} Kubernetes Orchestrator store types via the Keyfactor Command
# REST API using curl.
#
# Authentication (first matching method is used):
#   OAuth access token:     KEYFACTOR_AUTH_ACCESS_TOKEN
#   OAuth client creds:     KEYFACTOR_AUTH_CLIENT_ID + KEYFACTOR_AUTH_CLIENT_SECRET
#                           + KEYFACTOR_AUTH_TOKEN_URL
#   Basic auth (AD):        KEYFACTOR_USERNAME + KEYFACTOR_PASSWORD + KEYFACTOR_DOMAIN
#
# Always required:
#   KEYFACTOR_HOSTNAME      Command hostname (e.g. my-command.example.com)
#
# Auto-generated from integration-manifest.json — do not edit by hand.
# Regenerate with: make store-types-gen-scripts

if [ -z "${{KEYFACTOR_HOSTNAME}}" ]; then
    echo "ERROR: KEYFACTOR_HOSTNAME is required"
    exit 1
fi

BASE_URL="https://${{KEYFACTOR_HOSTNAME}}/keyfactorapi"

# ---------------------------------------------------------------------------
# Resolve auth
# ---------------------------------------------------------------------------
if [ -n "${{KEYFACTOR_AUTH_ACCESS_TOKEN}}" ]; then
    BEARER_TOKEN="${{KEYFACTOR_AUTH_ACCESS_TOKEN}}"
elif [ -n "${{KEYFACTOR_AUTH_CLIENT_ID}}" ] && [ -n "${{KEYFACTOR_AUTH_CLIENT_SECRET}}" ] && [ -n "${{KEYFACTOR_AUTH_TOKEN_URL}}" ]; then
    echo "Fetching OAuth token..."
    BEARER_TOKEN=$(curl -s -X POST "${{KEYFACTOR_AUTH_TOKEN_URL}}" \\
        -H "Content-Type: application/x-www-form-urlencoded" \\
        --data-urlencode "grant_type=client_credentials" \\
        --data-urlencode "client_id=${{KEYFACTOR_AUTH_CLIENT_ID}}" \\
        --data-urlencode "client_secret=${{KEYFACTOR_AUTH_CLIENT_SECRET}}" | jq -r '.access_token')
    if [ -z "${{BEARER_TOKEN}}" ] || [ "${{BEARER_TOKEN}}" = "null" ]; then
        echo "ERROR: Failed to fetch OAuth token from ${{KEYFACTOR_AUTH_TOKEN_URL}}"
        exit 1
    fi
elif [ -n "${{KEYFACTOR_USERNAME}}" ] && [ -n "${{KEYFACTOR_PASSWORD}}" ] && [ -n "${{KEYFACTOR_DOMAIN}}" ]; then
    BEARER_TOKEN=""
else
    echo "ERROR: Authentication required. Set one of:"
    echo "  KEYFACTOR_AUTH_ACCESS_TOKEN"
    echo "  KEYFACTOR_AUTH_CLIENT_ID + KEYFACTOR_AUTH_CLIENT_SECRET + KEYFACTOR_AUTH_TOKEN_URL"
    echo "  KEYFACTOR_USERNAME + KEYFACTOR_PASSWORD + KEYFACTOR_DOMAIN"
    exit 1
fi

if [ -n "${{BEARER_TOKEN}}" ]; then
    CURL_AUTH=("-H" "Authorization: Bearer ${{BEARER_TOKEN}}")
else
    CURL_AUTH=("-u" "${{KEYFACTOR_USERNAME}}@${{KEYFACTOR_DOMAIN}}:${{KEYFACTOR_PASSWORD}}")
fi

create_store_type() {{
    local name="$1"
    local body="$2"
    echo "Creating ${{name}} store type..."
    response=$(curl -s -o /dev/null -w "%{{http_code}}" \\
        -X POST "${{BASE_URL}}/certificatestoretypes" \\
        -H "Content-Type: application/json" \\
        -H "x-keyfactor-requested-with: APIClient" \\
        "${{CURL_AUTH[@]}}" \\
        -d "${{body}}")
    if [ "$response" = "200" ] || [ "$response" = "201" ]; then
        echo "  OK (HTTP ${{response}})"
    else
        echo "  FAILED (HTTP ${{response}})"
    fi
}}

"""

CURL_BASH_FOOTER = '\necho "Completed."\n'
CURL_DIVIDER = "# " + "-" * 75


def gen_curl_bash(store_types):
    lines = [CURL_BASH_HEADER.format(count=len(store_types))]
    for st in store_types:
        name = st["ShortName"]
        desc = st.get("ClientMachineDescription", name)
        body = store_type_json(st)
        lines.append(f"{CURL_DIVIDER}\n")
        lines.append(f"# {name} — {desc}\n")
        lines.append(f"{CURL_DIVIDER}\n")
        lines.append(f"create_store_type \"{name}\" '{body}'\n\n")
    lines.append(CURL_BASH_FOOTER)
    return "".join(lines)


# ---------------------------------------------------------------------------
# REST PowerShell
# ---------------------------------------------------------------------------
REST_PS_HEADER = """\
# Creates all {count} Kubernetes Orchestrator store types via the Keyfactor Command
# REST API using PowerShell Invoke-RestMethod.
#
# Authentication (first matching method is used):
#   OAuth access token:     KEYFACTOR_AUTH_ACCESS_TOKEN
#   OAuth client creds:     KEYFACTOR_AUTH_CLIENT_ID + KEYFACTOR_AUTH_CLIENT_SECRET
#                           + KEYFACTOR_AUTH_TOKEN_URL
#   Basic auth (AD):        KEYFACTOR_USERNAME + KEYFACTOR_PASSWORD + KEYFACTOR_DOMAIN
#
# Always required:
#   KEYFACTOR_HOSTNAME      Command hostname (e.g. my-command.example.com)
#
# Auto-generated from integration-manifest.json — do not edit by hand.
# Regenerate with: make store-types-gen-scripts

if (-not $env:KEYFACTOR_HOSTNAME) {{
    Write-Error "KEYFACTOR_HOSTNAME is required"
    exit 1
}}

$uri     = "https://$($env:KEYFACTOR_HOSTNAME)/keyfactorapi/certificatestoretypes"
$headers = @{{
    'Content-Type'               = "application/json"
    'x-keyfactor-requested-with' = "APIClient"
}}

# ---------------------------------------------------------------------------
# Resolve auth
# ---------------------------------------------------------------------------
if ($env:KEYFACTOR_AUTH_ACCESS_TOKEN) {{
    $headers['Authorization'] = "Bearer $($env:KEYFACTOR_AUTH_ACCESS_TOKEN)"
}} elseif ($env:KEYFACTOR_AUTH_CLIENT_ID -and $env:KEYFACTOR_AUTH_CLIENT_SECRET -and $env:KEYFACTOR_AUTH_TOKEN_URL) {{
    Write-Host "Fetching OAuth token..."
    $tokenBody = @{{
        grant_type    = 'client_credentials'
        client_id     = $env:KEYFACTOR_AUTH_CLIENT_ID
        client_secret = $env:KEYFACTOR_AUTH_CLIENT_SECRET
    }}
    $tokenResp = Invoke-RestMethod -Method Post -Uri $env:KEYFACTOR_AUTH_TOKEN_URL -Body $tokenBody
    $headers['Authorization'] = "Bearer $($tokenResp.access_token)"
}} elseif ($env:KEYFACTOR_USERNAME -and $env:KEYFACTOR_PASSWORD -and $env:KEYFACTOR_DOMAIN) {{
    $cred = [System.Convert]::ToBase64String(
        [System.Text.Encoding]::ASCII.GetBytes(
            "$($env:KEYFACTOR_USERNAME)@$($env:KEYFACTOR_DOMAIN):$($env:KEYFACTOR_PASSWORD)"))
    $headers['Authorization'] = "Basic $cred"
}} else {{
    Write-Error "Authentication required. Set one of:`n  KEYFACTOR_AUTH_ACCESS_TOKEN`n  KEYFACTOR_AUTH_CLIENT_ID + KEYFACTOR_AUTH_CLIENT_SECRET + KEYFACTOR_AUTH_TOKEN_URL`n  KEYFACTOR_USERNAME + KEYFACTOR_PASSWORD + KEYFACTOR_DOMAIN"
    exit 1
}}

function New-StoreType {{
    param([string]$Name, [string]$Body)
    Write-Host "Creating $Name store type..."
    try {{
        Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $Body -ContentType "application/json" | Out-Null
        Write-Host "  OK"
    }} catch {{
        Write-Warning "  FAILED: $($_.Exception.Message)"
    }}
}}

"""

REST_PS_FOOTER = '\nWrite-Host "Completed."\n'
PS_DIVIDER = "# " + "-" * 75


def gen_rest_ps(store_types):
    lines = [REST_PS_HEADER.format(count=len(store_types))]
    for st in store_types:
        name = st["ShortName"]
        desc = st.get("ClientMachineDescription", name)
        body = store_type_json(st)
        lines.append(f"{PS_DIVIDER}\n")
        lines.append(f"# {name} — {desc}\n")
        lines.append(f"{PS_DIVIDER}\n")
        lines.append(f"New-StoreType \"{name}\" @'\n{body}\n'@\n\n")
    lines.append(REST_PS_FOOTER)
    return "".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="\n") as f:
        f.write(content)
    print(f"  wrote {os.path.relpath(path)}")


def generate(manifest_path=MANIFEST, bash_dir=BASH_DIR, ps_dir=PS_DIR):
    store_types = load_store_types(manifest_path)
    print(f"Loaded {len(store_types)} store types from {manifest_path}")

    write(os.path.join(bash_dir, "kfutil_create_store_types.sh"),      gen_kfutil_bash(store_types))
    write(os.path.join(bash_dir, "curl_create_store_types.sh"),        gen_curl_bash(store_types))
    write(os.path.join(ps_dir,   "kfutil_create_store_types.ps1"),     gen_kfutil_ps(store_types))
    write(os.path.join(ps_dir,   "restmethod_create_store_types.ps1"), gen_rest_ps(store_types))

    for f in ["kfutil_create_store_types.sh", "curl_create_store_types.sh"]:
        os.chmod(os.path.join(bash_dir, f), 0o755)

    print("Done.")


if __name__ == "__main__":
    generate()
