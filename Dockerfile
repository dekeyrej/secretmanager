#Builder stage
FROM python:slim AS builder
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY requirements.txt .
RUN . /opt/venv/bin/activate
RUN pip install -r requirements.txt
RUN pip install dekeyrej-secretmanager
COPY tools/check_and_append_cacert.py .
COPY tools/certs/ca.crt ./certs/ca.crt
RUN python check_and_append_cacert.py
#Operational stage
FROM python:slim
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1
WORKDIR /code
COPY tools/recryptonator.py .
# COPY secretmanager/ .
CMD ["sh", "-c", "python /code/recryptonator.py"]