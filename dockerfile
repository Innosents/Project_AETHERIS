# Base OS: Alpine Linux for zero-padding minimal footprint
FROM python:3.10-alpine

# Enforce strict environmental variables
ENV PYTHONUNBUFFERED=1

# Install libpcap for Scapy Layer 2 socket injection
RUN apk add --no-cache tcpdump libpcap-dev gcc musl-dev linux-headers

# Establish the execution boundary
WORKDIR /aetheris_harness

# Install Scapy mapping library
RUN pip install --no-cache-dir scapy

# Inject the synthetic beacon
COPY beacon.py .

# Execute the transmission matrix
CMD ["python", "beacon.py"]