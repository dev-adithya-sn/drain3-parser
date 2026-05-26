FROM python:3.12-slim

# install vector
RUN apt-get update && apt-get install -y curl && \
    curl --proto '=https' --tlsv1.2 -sSfL https://sh.vector.dev | bash -s -- -y && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
ENV PATH="/root/.vector/bin:${PATH}"

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD uvicorn webapp.server:app --host 0.0.0.0 --port ${PORT:-8000}
