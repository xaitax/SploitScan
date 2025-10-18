FROM python:3.13-slim-trixie

LABEL version="0.14.2"
LABEL description="SploitScan is a powerful and user-friendly tool designed to streamline the process of identifying exploits for known vulnerabilities and their respective exploitation probability"

ARG DEBIAN_FRONTEND=noninteractive

# Setting up venv
ENV VENV=/venv
ENV PATH=${VENV}/bin:${PATH}

# Installing packages including git
RUN apt-get update && \
    apt-get install --yes --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

# Downloading and installing dependencies
COPY ./requirements.txt .

RUN python -m venv ${VENV} && \
    pip install --upgrade pip setuptools && \
    pip install --no-cache-dir -r requirements.txt

ENV APP_HOME=/app

# Copy application files
WORKDIR $APP_HOME
COPY ./sploitscan ./sploitscan
COPY ./sploitscan.py .
COPY ./LICENSE .
COPY ./CHANGELOG.md .

# Make a directory for scan results
RUN mkdir /results

# Start the application
ENTRYPOINT ["python", "sploitscan.py"]
CMD ["-h"]
