FROM python:3.11-slim

RUN pip install --no-cache-dir flask gunicorn && \
    apt-get update && apt-get install -y --no-install-recommends nginx && \
    rm -rf /var/lib/apt/lists/*

COPY app.py /app/app.py

RUN echo 'server { \
    listen 80; \
    location / { \
        proxy_pass http://127.0.0.1:8080; \
        proxy_set_header Host $host; \
    } \
}' > /etc/nginx/sites-available/default

EXPOSE 80

CMD sh -c "gunicorn -b 127.0.0.1:8080 -w 2 app:app --chdir /app & nginx -g 'daemon off;'"
