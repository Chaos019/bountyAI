# BountyAI v3 — pure Python stdlib, zero external dependencies.
# (The old Dockerfile referenced FastAPI/uvicorn, which are NOT part of this
#  project and were never installed — see requirements.txt.)
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# curl/unzip for the nuclei binary, git for the template catalog.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl unzip git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# requirements.txt is intentionally empty (stdlib only); kept for Render/CI detection.
COPY ./bountyai/server/requirements.txt ./

# Copy the whole app (server + frontend)
COPY ./bountyai ./bountyai

# nuclei binary + its template catalog (both are gitignored, so they are
# fetched at build time instead of being committed).
RUN curl -sL https://github.com/projectdiscovery/nuclei/releases/download/v3.1.1/nuclei_3.1.1_linux_amd64.zip -o /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip nuclei -d bountyai/server/ \
    && chmod +x bountyai/server/nuclei \
    && rm /tmp/nuclei.zip \
    && git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git bountyai/server/nuclei-templates

# Server binds $PORT (default 5000) and serves the frontend + API
EXPOSE 5000

CMD ["python", "-u", "bountyai/server/server.py"]
