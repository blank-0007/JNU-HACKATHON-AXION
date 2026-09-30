# Verifier: deploys the ledger, enrolls the agent, serves the dashboard.
FROM python:3.12-slim
RUN pip install --no-cache-dir "streamlit>=1.40,<2" "web3>=7,<8"
WORKDIR /app
COPY . .
ENV PYTHONUNBUFFERED=1
EXPOSE 8501
CMD ["sh", "-c", "python deploy.py && exec streamlit run app.py"]
