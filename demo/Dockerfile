FROM python:3.11-slim
WORKDIR /app
COPY . /app
# One service: app.py launches the bundled verified wallet internally,
# then serves the product UI + Factory dashboard on $PORT (Render sets it).
CMD ["python", "app.py"]
