FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY zbx_migration_checker ./zbx_migration_checker
ENTRYPOINT ["python", "-m", "zbx_migration_checker"]
