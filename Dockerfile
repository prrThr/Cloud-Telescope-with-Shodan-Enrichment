FROM debian:trixie-slim

LABEL maintainer="cloud-telescope"
LABEL description="IBR ETL pipeline — tshark + GeoIP2 + MySQL"

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# ── Pré-configura o tshark para não pedir EULA interativa ──
# Cria o grupo wireshark antes do apt para evitar falha no
# post-install script do wireshark-common dentro do Docker
RUN groupadd -r wireshark && \
    echo "wireshark-common wireshark-common/install-setuid boolean true" \
        | debconf-set-selections

# ── Pacotes de sistema ──────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    tcpreplay \
    gzip \
    unzip \
    procps \
    time \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    build-essential \
    gcc \
    g++ \
    make \
    pkg-config \
    libssl-dev \
    libffi-dev \
    default-mysql-client \
    texlive-latex-base \
    texlive-latex-recommended \
    vim \
    git \
    curl \
    wget \
    less \
    htop \
    tree \
    jq \
    ripgrep \
    net-tools \
    iputils-ping \
    dnsutils \
    strace \
    lsof \
    file \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── Venv isolado (Debian 13 bloqueia pip direto no sistema) ──
ENV VENV=/opt/venv
RUN python3 -m venv $VENV
ENV PATH="$VENV/bin:$PATH"

# ── Pacotes Python do pipeline ───────────────────────────────
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
        geoip2 \
        awsipranges \
        mysql-connector-python \
        pandas \
        seaborn \
        matplotlib \
        ipython

# ── Espelha a estrutura real do projeto no container ─────────
#
#   /ibr-etl/          → raiz do projeto (montado via volume no compose)
#   /ibr-etl/other/    → scripts auxiliares
#   /ibr-etl/e1/       → pcap.gz raw
#   /ibr-etl/e3/       → pcap.gz compactados
#
#   O GeoIP2-City.mmdb deve ficar na raiz /ibr-etl/
#   (mesmo local de onde os scripts são invocados)

RUN mkdir -p /ibr-etl/e1/ /ibr-etl/e3/ /ibr-etl/other

WORKDIR /ibr-etl

CMD ["/bin/bash"]
