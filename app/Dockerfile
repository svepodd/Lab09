FROM python:3.11-slim
WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        libjpeg-dev zlib1g-dev \
        libxml2-dev libxslt1-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY . /app
EXPOSE 8080

# FIX (CKV_DOCKER_3): создаём непривилегированного пользователя и
# переключаемся на него — контейнер больше не работает под root.
RUN adduser --disabled-password --gecos "" appuser
USER appuser

# FIX (CKV_DOCKER_2): добавляем HEALTHCHECK, чтобы оркестратор мог
# определять работоспособность контейнера.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/').read()" || exit 1

# Debug по умолчанию выключен (управляется переменной окружения в app.py)
CMD ["python", "app.py"]
