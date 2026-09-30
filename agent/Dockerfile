# Stage 1: build the protected service as a static binary.
FROM alpine:3.20 AS build
RUN apk add --no-cache build-base
COPY checkout_service.c /src/
RUN gcc -O2 -static -o /out-checkout-service /src/checkout_service.c

# Stage 2: the integrity agent.
FROM python:3.12-slim
RUN pip install --no-cache-dir "web3>=7,<8"
COPY --from=build /out-checkout-service /opt/pristine/checkout-service
WORKDIR /app
COPY agent.py ./
ENV PYTHONUNBUFFERED=1
CMD ["python", "agent.py"]
