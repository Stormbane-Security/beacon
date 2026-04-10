FROM python:3.12-slim
RUN pip install --no-cache-dir django==5.0
WORKDIR /app
COPY app.py /app/app.py
EXPOSE 8000
CMD ["python", "app.py"]
