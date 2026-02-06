# VexHelix — Bounded Relational Symbolic Execution for Decompilation Verification
# Ubuntu 24.04 · Python 3.12 · GCC/G++ 13 · angr

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_BREAK_SYSTEM_PACKAGES=1

WORKDIR /app

# ── system packages ──────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3.12 python3.12-dev python3-pip \
        gcc g++ make git curl \
        libffi-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN ln -sf /usr/bin/python3.12 /usr/bin/python3 \
 && ln -sf /usr/bin/python3.12 /usr/bin/python

RUN python3 -m pip install --upgrade pip setuptools wheel

# ── python deps (cached layer) ───────────────────────────────────────────────
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# ── application code ─────────────────────────────────────────────────────────
COPY pyproject.toml /app/pyproject.toml
COPY vexhelix/      /app/vexhelix/
RUN pip install --no-cache-dir -e .

# ── runtime ──────────────────────────────────────────────────────────────────
RUN mkdir -p /tmp/vexhelix && chmod 777 /tmp/vexhelix

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:8000/health || exit 1

CMD ["uvicorn", "vexhelix.api.server:app", \
     "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
