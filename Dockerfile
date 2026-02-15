FROM kalilinux/kali-rolling:latest

# Base packages + Go + Tools
RUN --mount=type=cache,target=/var/cache/apt \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    python3-pip \
    figlet \
    sudo \
    golang-go \
    ffuf \
    boxes \
    php \
    curl \
    xdotool \
    wget \
    nmap \
    sqlmap \
    nikto \
    metasploit-framework \
    hydra \
    john \
    aircrack-ng \
    wifite \
    wireshark \
    dsniff \
    ettercap-text-only \
    fcrackzip \
    net-tools \
    dnsutils \
    whois \
    proxychains4 \
    tor \
    ssh \
    build-essential \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Set Go environment
ENV GOPATH=/root/go
ENV PATH="${GOPATH}/bin:${PATH}"

# Install Modern Tools (Go-based)
RUN --mount=type=cache,target=/root/go/pkg/mod \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/jaeles-project/gospider@latest

WORKDIR /root/hackingtool

COPY requirements.txt .

RUN --mount=type=cache,target=/root/.cache/pip \
    pip3 install --break-system-packages -r requirements.txt

COPY . .
RUN echo "/root/hackingtool/" > /home/hackingtoolpath.txt

EXPOSE 1-65535
ENTRYPOINT ["python3", "/root/hackingtool/hackingtool.py"]
