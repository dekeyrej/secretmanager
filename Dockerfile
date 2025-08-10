#Builder stage
FROM python:slim AS builder
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN . /opt/venv/bin/activate
WORKDIR /code
COPY requirements.txt .
RUN pip install -r requirements.txt
RUN pip install dekeyrej-secretmanager
COPY tools/check_and_append_cacert.py tools/
COPY tools/certs/ca.crt tools/certs/ca.crt
RUN python tools/check_and_append_cacert.py
#Operational stage
FROM python:slim
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1
WORKDIR /code
COPY tools/recryptonator.py .
CMD ["sh", "-c", "python /code/recryptonator.py"]