#Builder stage
FROM python:3.12-slim AS builder
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY requirements.txt .
RUN . /opt/venv/bin/activate
RUN pip install -r requirements.txt
# COPY examples/vault_ssl_support/check_and_append_cacert.py .
# COPY examples/vault_ssl_support/ca.crt .
# RUN python check_and_append_cacert.py
#Operational stage
FROM python:3.12-slim
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1
WORKDIR /code
COPY examples/recryptonator/recryptonator.py .
COPY secretmanager/secretmanager.py .
COPY ca.crt .
CMD ["sh", "-c", "python /code/recryptonator.py"]