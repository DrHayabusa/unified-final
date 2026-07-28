# MVA Unified Vulnerability Management Platform

Production React, FastAPI, and PostgreSQL platform for tenant-isolated vulnerability reporting, remediation, asset inventory, host-discovery coverage, and private AI generation.

## Runtime architecture

```mermaid
flowchart LR
    U["Analyst browser"] -->|"HTTPS"| P["Reverse proxy"]
    P --> A["MVA FastAPI + built React UI"]
    A -->|"SQL, private network"| D[("PostgreSQL 17")]
    A -->|"HTTP(S), server-side only"| L["Local Ollama or OpenAI-compatible AI"]
    U -. "CSV/XLSX parsing and local report rendering" .-> U
```

- React parses scanner files, normalizes findings, calculates P1-P4, compares reporting periods, and renders local Excel/PDF outputs in the browser.
- Every adhoc, monthly, and quarterly workflow includes a line chart. Dated exports use discovery history; undated adhoc exports show the current severity profile without inventing historical values.
- Custom Qualys reports preserve the five approved source ratings and Datacentre distribution in both Excel and executive PDF output.
- FastAPI owns authentication, CSRF protection, authorization, tenant boundaries, asset inventory, scan history, CSV exports, threat-intelligence storage, and AI requests.
- PostgreSQL stores users, tenants, memberships, teams, inventory, normalized finding history, sessions, threat intelligence, and audit events.
- The browser never receives the database password or AI key.

## Local production-style run on port 8890

1. Open Terminal in this repository.
2. Create local secrets:

```bash
mkdir -p secrets
openssl rand -base64 36 > secrets/database_password.txt
: > secrets/ai_api_key.txt
```

3. Create the local environment file:

```bash
cp .env.production.example .env
```

4. For direct HTTP testing only, edit `.env`:

```dotenv
APP_ENV=development
COOKIE_SECURE=false
TRUSTED_HOSTS=127.0.0.1,localhost
CORS_ORIGINS=http://127.0.0.1:8890
AI_API_STYLE=ollama
AI_BASE_URL=http://host.docker.internal:11434
AI_MODEL=gemma3:12b
```

5. Start:

```bash
docker compose --env-file .env -f compose.production.yml up --build -d
docker compose --env-file .env -f compose.production.yml ps
```

6. Open `http://127.0.0.1:8890` and create the first system administrator.

7. Stop without deleting data:

```bash
docker compose --env-file .env -f compose.production.yml down
```

## Production deployment

1. Put the platform behind your approved HTTPS reverse proxy.
2. Copy `.env.production.example` to `.env`.
3. Keep `APP_ENV=production` and `COOKIE_SECURE=true`.
4. Set `TRUSTED_HOSTS` to the exact MVA hostname.
5. Set `CORS_ORIGINS` to the exact HTTPS origin.
6. Keep `MVA_BIND_ADDRESS=127.0.0.1` when the reverse proxy is on the same host.
7. Generate `secrets/database_password.txt`; never commit it.
8. Configure AI as described below.
9. Run the same Docker Compose command.
10. Back up the `mva_postgres_data` volume according to the organization backup policy.

The database port is not published. Permit inbound HTTPS only to the reverse proxy and outbound traffic from the MVA app to the configured AI endpoint.

## Central AI integration

Normal integration requires editing only `.env` and the secret file. All AI calls are centralized in `backend/local_llm.py`; the API routes in `backend/app.py` call that adapter.

### Native Ollama

```dotenv
AI_API_STYLE=ollama
AI_BASE_URL=http://ai-server.internal:11434
AI_MODEL=gemma3:12b
AI_TIMEOUT_SECONDS=600
AI_TLS_VERIFY=true
```

Leave `secrets/ai_api_key.txt` empty when Ollama does not require authentication. If a gateway requires a token, put only the token in that file:

```bash
printf '%s' 'REPLACE_WITH_SERVER_TOKEN' > secrets/ai_api_key.txt
chmod 600 secrets/*.txt
```

FastAPI calls:

- Connectivity: `GET {AI_BASE_URL}/api/tags`
- Remediation and intelligence: `POST {AI_BASE_URL}/api/chat`

### OpenAI-compatible local server

```dotenv
AI_API_STYLE=openai
AI_BASE_URL=https://ai-server.internal/v1
AI_MODEL=organization/model-name
AI_AUTH_HEADER=Authorization
AI_AUTH_SCHEME=Bearer
AI_TIMEOUT_SECONDS=600
AI_TLS_VERIFY=true
```

Put the server token in `secrets/ai_api_key.txt`. FastAPI calls:

- Connectivity: `GET {AI_BASE_URL}/models`
- Remediation and intelligence: `POST {AI_BASE_URL}/chat/completions`

Do not hard-code a key in React, `backend/app.py`, or Git. Edit `backend/local_llm.py` only when the internal service is neither native Ollama nor OpenAI-compatible.

### AI request workflow

```mermaid
sequenceDiagram
    participant B as Browser
    participant A as FastAPI
    participant I as Private AI
    B->>A: POST remediation or intelligence + session cookie + CSRF
    A->>A: Verify user, tenant, role, and bounded payload
    A->>I: Server-side request with model and secret header
    I-->>A: Markdown or JSON response
    A->>A: Write audit event
    A-->>B: Approved response only
    B->>B: Render and download PDF locally
```

Use the **LLM Configuration** page to test this route after sign-in. The test is performed by FastAPI, not by the browser.

## Manual developer run

PostgreSQL must already be available.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cd frontend
npm ci
npm run build
cd ..
export APP_ENV=development
export COOKIE_SECURE=false
export PORT=8890
export FRONTEND_DIST="$PWD/frontend/dist"
export DATABASE_URL='postgresql://mva:password@127.0.0.1:5432/mva'
python -m uvicorn backend.app:app --host 127.0.0.1 --port 8890
```

## Production source layout

- `frontend/src/`: React components, scanner parsers, charts, Excel/PDF generators, and API client.
- `frontend/vite.config.js`: Vite, Tailwind, and production bundling configuration.
- `backend/app.py`: all HTTP routes, security middleware, sessions, authorization, and AI orchestration.
- `backend/local_llm.py`: the single outbound AI adapter.
- `backend/repository.py`: tenant-scoped PostgreSQL operations.
- `backend/schema.py`: idempotent database schema.
- `backend/validation.py`: bounded request and normalized finding validation.
- `compose.production.yml`: hardened application and PostgreSQL deployment.

No scanner samples, test fixtures, provider keys, database passwords, or customer data are included.
