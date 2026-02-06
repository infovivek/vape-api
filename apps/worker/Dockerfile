FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY apps/api /app/apps/api
COPY apps/worker /app/apps/worker
COPY packages/shared /app/packages/shared
ENV PYTHONPATH=/app
CMD ["celery", "-A", "apps.api.app.tasks.celery_app", "worker", "--loglevel=info"]
