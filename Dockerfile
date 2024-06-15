FROM python:3.9-slim-buster

WORKDIR /app
COPY . /app
COPY sploitscan/config.json /app/config.json
RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT ["python", "sploitscan.py"]
