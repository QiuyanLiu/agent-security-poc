FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

RUN groupadd --system --gid 10001 agentgroup \
    && useradd --system \
        --uid 10001 \
        --gid agentgroup \
        --home-dir /app \
        --shell /usr/sbin/nologin \
        agentuser \
    && chown -R root:root /app \
    && chmod 0555 /app \
    && chmod 0444 /app/server.py /app/requirements.txt

USER agentuser

CMD ["python", "server.py"]