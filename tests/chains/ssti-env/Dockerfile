FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir flask jinja2
COPY app.py .
EXPOSE 8080
CMD ["python", "app.py"]
