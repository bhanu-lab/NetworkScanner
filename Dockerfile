FROM python:3.13-slim
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 iputils-ping && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV HOST=0.0.0.0 PORT=5000
EXPOSE 5000
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "4", "--timeout", "180", "main:scanner"]
