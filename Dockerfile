# Build context = owner_panel/
FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8787 CROWNAUTH_DATA=/tmp/crowndata

COPY requirements-cloud.txt .
RUN pip install --no-cache-dir -r requirements-cloud.txt

COPY crownauth ./crownauth
COPY cloud_entry.py .

# Free Render has no persistent disk — DB lives in container filesystem.
# Acceptable for free tier; export backups from panel regularly.
RUN mkdir -p /tmp/crowndata /tmp/crowndata/secrets
EXPOSE 8787
CMD ["python", "cloud_entry.py"]
