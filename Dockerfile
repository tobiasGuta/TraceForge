FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 TRACEFORGE_DATA_DIR=/data
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --uid 10001 --create-home traceforge \
    && mkdir -p /data && chown traceforge:traceforge /data
COPY backend ./backend
COPY frontend ./frontend
ENV PYTHONPATH=/app/backend
USER traceforge
EXPOSE 8000
CMD ["uvicorn", "traceforge.app:app", "--host", "0.0.0.0", "--port", "8000"]
