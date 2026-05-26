FROM python:3.12-slim

# install vector binary
RUN apt-get update && \
    apt-get install -y curl && \
    curl -sSfL https://packages.timber.io/vector/0.44.0/vector-0.44.0-x86_64-unknown-linux-gnu.tar.gz | \
    tar xzf - --strip-components=2 -C /usr/local/bin/ ./vector-0.44.0-x86_64-unknown-linux-gnu/bin/vector && \
    apt-get remove -y curl && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
