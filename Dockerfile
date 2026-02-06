FROM kalilinux/kali-rolling:latest

# Base packages + Go
RUN --mount=type=cache,target=/var/cache/apt \
    apt-get update && \
    apt-get install -y git python3-pip figlet sudo golang-go ffuf && \
    apt-get install -y boxes php curl xdotool wget nmap

# Set Go environment
ENV GOPATH=/root/go
ENV PATH="${GOPATH}/bin:${PATH}"

# Install Modern Tools (Go-based)
RUN --mount=type=cache,target=/root/go/pkg/mod \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/jaeles-project/gospider@latest

WORKDIR /root/hackingtool
COPY requirements.txt ./
RUN --mount=type=cache,target=/root/.cache/pip \
    pip3 install --break-system-packages boxes flask lolcat requests arjun -r requirements.txt
COPY . .
RUN echo "/root/hackingtool/" > /home/hackingtoolpath.txt

EXPOSE 1-65535
ENTRYPOINT ["python3", "/root/hackingtool/hackingtool.py"]
