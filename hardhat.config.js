// Hardhat is only used to compile the contract and run a local chain.
// Deployment is done from Python (deploy.py) so the same hashing code
// anchors the file and later verifies it.
module.exports = {
  solidity: "0.8.24",
  networks: {
    localhost: { url: "http://127.0.0.1:8545" }, // `npx hardhat node`, chain id 31337
  },
};
