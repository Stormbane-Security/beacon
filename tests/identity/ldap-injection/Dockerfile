FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends libldap2-dev libsasl2-dev gcc && \
    pip install --no-cache-dir flask python-ldap && \
    apt-get purge -y gcc && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY app.py .
EXPOSE 8080
CMD ["python", "app.py"]
