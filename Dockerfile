FROM python:3.12-slim
WORKDIR /app
COPY secret_detect.py rules.json config.json ./
ENTRYPOINT ["python", "secret_detect.py"]
CMD ["--help"]
