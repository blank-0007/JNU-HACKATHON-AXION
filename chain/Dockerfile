# Local blockchain: Hardhat node + the compiled IntegrityLedger artifact.
FROM node:22-slim
ENV HARDHAT_DISABLE_TELEMETRY_PROMPT=true
WORKDIR /chain
COPY package.json package-lock.json ./
RUN npm ci --no-fund --no-audit
COPY hardhat.config.js ./
COPY contracts ./contracts
RUN node_modules/.bin/hardhat compile
EXPOSE 8545
# Publish the ABI/bytecode to the shared volume so the verifier can deploy it.
CMD ["sh", "-c", "cp artifacts/contracts/IntegrityLedger.sol/IntegrityLedger.json /shared/ && exec node_modules/.bin/hardhat node --hostname 0.0.0.0"]
