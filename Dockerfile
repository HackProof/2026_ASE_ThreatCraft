FROM debian:bookworm-slim

ARG UID=1000
ARG GID=1000

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DISPLAY=:99 \
    SCREEN_GEOMETRY=1600x1000x24 \
    XDG_RUNTIME_DIR=/tmp/runtime-threatcraft \
    BROWSER=firefox-esr \
    PATH=/opt/venv/bin:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    python3-tk \
    graphviz \
    xvfb \
    x11vnc \
    openbox \
    novnc \
    websockify \
    x11-utils \
    xdg-utils \
    firefox-esr \
    fonts-dejavu-core \
    fonts-liberation \
    fonts-noto-cjk \
    ca-certificates \
    curl \
    tini \
    libcairo2 \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid "${GID}" threatcraft \
    && useradd \
        --uid "${UID}" \
        --gid "${GID}" \
        --create-home \
        --shell /bin/bash \
        threatcraft

WORKDIR /app

COPY requirements-docker.txt /tmp/requirements-docker.txt

RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip setuptools wheel \
    && /opt/venv/bin/pip install \
        --no-cache-dir \
        -r /tmp/requirements-docker.txt

COPY --chown=threatcraft:threatcraft . /app

RUN mkdir -p \
        /workspace \
        /app/code/frontend/out \
        /tmp/runtime-threatcraft \
    && chown -R threatcraft:threatcraft \
        /workspace \
        /app/code/frontend/out \
        /tmp/runtime-threatcraft

COPY --chown=threatcraft:threatcraft \
    docker/entrypoint.sh \
    /usr/local/bin/threatcraft-entrypoint

RUN chmod +x /usr/local/bin/threatcraft-entrypoint

USER threatcraft

EXPOSE 6080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:6080/vnc.html >/dev/null || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/threatcraft-entrypoint"]
