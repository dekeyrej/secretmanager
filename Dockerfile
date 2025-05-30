#Builder stage
FROM python:3.12-slim AS builder
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY requirements.txt .
RUN . /opt/venv/bin/activate
RUN pip install -r requirements.txt
#Operational stage
FROM python:3.12-slim
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PROD=1 \
    PYTHONUNBUFFERED=1
WORKDIR /code
COPY recryptonator.py .
COPY secretmanager.py .
COPY ca.crt .
CMD ["sh", "-c", "python /code/recryptonator.py"]