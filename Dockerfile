FROM python:3.12.13-alpine3.23

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY script.py .

ENTRYPOINT [ "python", "-u", "/app/script.py" ]