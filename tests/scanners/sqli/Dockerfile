FROM python:3.12-alpine
RUN pip install --no-cache-dir flask
COPY app.py /app/app.py
WORKDIR /app
EXPOSE 8080
CMD ["python", "app.py"]
