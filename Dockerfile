FROM zeek/zeek:8.2

ENV PATH="/opt/zeek/bin:${PATH}" \
    DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    JA4_2_DATA_ROOT=/data \
    JA4_2_DB_PATH=/data/db/ja-bench.sqlite3 \
    FLASK_APP=app.main:create_app

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        git \
        perl \
        python3 \
        python3-pip \
        python3-venv \
        sqlite3 \
        tcpdump \
        tshark \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN python3 -m pip install --break-system-packages -r /app/requirements.txt

COPY . /app

RUN chmod +x /app/entrypoint.sh \
    && yes '' | zkg autoconfig \
    && zkg install --force zeek/foxio/ja4

EXPOSE 5000

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["python3", "-m", "flask", "run", "--host=0.0.0.0", "--port=5000"]
