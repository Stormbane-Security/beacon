FROM python:3.12-alpine
RUN pip install --no-cache-dir jinja2
WORKDIR /app
COPY server.py .
EXPOSE 8080
CMD ["python", "server.py"]
