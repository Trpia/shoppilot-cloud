FROM python:3.12-slim
WORKDIR /app
COPY app.py index.html ./
ENV DATA_DIR=/data
VOLUME /data
EXPOSE 8000
CMD ["python", "app.py"]
