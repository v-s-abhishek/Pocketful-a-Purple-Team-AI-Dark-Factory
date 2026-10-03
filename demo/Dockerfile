FROM python:3.11-slim
WORKDIR /app
COPY . /app
# PORT is provided by the host (Render); WALLET_URL points at the pocketful API.
CMD ["python", "app.py"]
