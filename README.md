# Multicaller

[![NPM][npm-shield]][npm-url]
[![CI][ci-shield]][ci-url]
[![MIT License][license-shield]][license-url]

Efficiently call multiple contracts in a single transaction.

Enables "forwarding" of `msg.sender` to the contracts called.

## Deployments

- Ethereum 
  - Multicaller: [`0x000000000000d991d267E53C7866fFA66DC2f61f`](https://etherscan.io/address/0x000000000000d991d267E53C7866fFA66DC2f61f)
  - MulticallerWithSender: [`0x00000000002Fd5Aeb385D324B580FCa7c83823A0`](https://etherscan.io/address/0x00000000002Fd5Aeb385D324B580FCa7c83823A0)
  - MulticallerWithSigner: [`0x0000000000005A3a8e2D745f0cDdEDC90946Ab1a`](https://etherscan.io/address/0x0000000000005A3a8e2D745f0cDdEDC90946Ab1a)
- Goerli 
  - Multicaller: [`0x000000000000d991d267E53C7866fFA66DC2f61f`](https://goerli.etherscan.io/address/0x000000000000d991d267E53C7866fFA66DC2f61f)
  - MulticallerWithSender: [`0x00000000002Fd5Aeb385D324B580FCa7c83823A0`](https://goerli.etherscan.io/address/0x00000000002Fd5Aeb385D324B580FCa7c83823A0)
  - MulticallerWithSigner: [`0x0000000000005A3a8e2D745f0cDdEDC90946Ab1a`](https://goerli.etherscan.io/address/0x0000000000005A3a8e2D745f0cDdEDC90946Ab1a)
- Sepolia 
  - Multicaller: [`0x000000000000d991d267E53C7866fFA66DC2f61f`](https://sepolia.etherscan.io/address/0x000000000000d991d267E53C7866fFA66DC2f61f)
  - MulticallerWithSender: [`0x00000000002Fd5Aeb385D324B580FCa7c83823A0`](https://sepolia.etherscan.io/address/0x00000000002Fd5Aeb385D324B580FCa7c83823A0)
  - MulticallerWithSigner: [`0x0000000000005A3a8e2D745f0cDdEDC90946Ab1a`](https://sepolia.etherscan.io/address/0x0000000000005A3a8e2D745f0cDdEDC90946Ab1a)
- Polygon 
  - Multicaller: [`0x000000000000d991d267E53C7866fFA66DC2f61f`](https://polygonscan.com/address/0x000000000000d991d267E53C7866fFA66DC2f61f)
  - MulticallerWithSender: [`0x00000000002Fd5Aeb385D324B580FCa7c83823A0`](https://polygonscan.com/address/0x00000000002Fd5Aeb385D324B580FCa7c83823A0)
  - MulticallerWithSigner: [`0x0000000000005A3a8e2D745f0cDdEDC90946Ab1a`](https://polygonscan.com/address/0x0000000000005A3a8e2D745f0cDdEDC90946Ab1a)
- Mumbai 
  - Multicaller: [`0x000000000000d991d267E53C7866fFA66DC2f61f`](https://mumbai.polygonscan.com/address/0x000000000000d991d267E53C7866fFA66DC2f61f)
  - MulticallerWithSender: [`0x00000000002Fd5Aeb385D324B580FCa7c83823A0`](https://mumbai.polygonscan.com/address/0x00000000002Fd5Aeb385D324B580FCa7c83823A0)
  - MulticallerWithSigner: [`0x0000000000005A3a8e2D745f0cDdEDC90946Ab1a`](https://mumbai.polygonscan.com/address/0x0000000000005A3a8e2D745f0cDdEDC90946Ab1a)
- Optimism 
  - Multicaller: [`0x000000000000d991d267E53C7866fFA66DC2f61f`](https://optimistic.etherscan.io/address/0x000000000000d991d267E53C7866fFA66DC2f61f)
  - MulticallerWithSender: [`0x00000000002Fd5Aeb385D324B580FCa7c83823A0`](https://optimistic.etherscan.io/address/0x00000000002Fd5Aeb385D324B580FCa7c83823A0)
  - MulticallerWithSigner: [`0x0000000000005A3a8e2D745f0cDdEDC90946Ab1a`](https://optimistic.etherscan.io/address/0x0000000000005A3a8e2D745f0cDdEDC90946Ab1a)
- Arbitrum 
  - Multicaller: [`0x000000000000d991d267E53C7866fFA66DC2f61f`](https://arbiscan.io/address/0x000000000000d991d267E53C7866fFA66DC2f61f)
  - MulticallerWithSender: [`0x00000000002Fd5Aeb385D324B580FCa7c83823A0`](https://arbiscan.io/address/0x00000000002Fd5Aeb385D324B580FCa7c83823A0)
  - MulticallerWithSigner: [`0x0000000000005A3a8e2D745f0cDdEDC90946Ab1a`](https://arbiscan.io/address/0x0000000000005A3a8e2D745f0cDdEDC90946Ab1a)

Please open an issue if you need help to deploy to an EVM chain of your choice.

## Contracts

```ml
src
├─ Multicaller.sol — "The multicaller contract"
├─ MulticallerWithSender.sol — "The multicaller with sender contract"
├─ MulticallerWithSigner.sol — "The multicaller with signer contract"
└─ LibMulticaller.sol — "Library to read the multicaller contracts"
``` 

## Installation

You can use the [`src/LibMulticaller.sol`](./src/LibMulticaller.sol) library in your contracts to query the multicaller with sender contract efficiently.

To install with [**Foundry**](https://github.com/gakonst/foundry):

```sh
forge install vectorized/multicaller
```

To install with [**Hardhat**](https://github.com/nomiclabs/hardhat) or [**Truffle**](https://github.com/trufflesuite/truffle):

```sh
npm install multicaller
```

## API

[The API docs](API.md).


## Design

The contracts are designed with a priority on efficiency and minimalism. 

- Multiple input calldata arrays instead of an array of structs for more compact calldata encoding.

- Omission of utility functions like `getBlockNumber` for more efficient function dispatch. If you need those functions, just add those functions into your contract, or read them off a separate utility contract like [MakerDao's Multicall](https://github.com/makerdao/multicall).

## Use Cases

For the following, the contracts called must read the `msg.sender` from the multicaller contract. 

The `LibMulticaller` library can be used for efficient reading.

**Example use cases:**

- Calling access role restricted functions across multiple contracts in a single transaction. 

- Approving a trusted operator contract to transfer tokens, and doing the transfer in a single transaction. 

  > **Warning** This will skip the approval warning on wallets. To mitigate phishing risk, you should make a custom approval function that validates a time-limited [EIP-712](https://eips.ethereum.org/EIPS/eip-712) signature signed by the `msg.sender`. 

## Safety

We **do not give any warranties** and **will not be liable for any loss** incurred through any use of this codebase.

## Acknowledgments

Multicaller is inspired by and directly modified from:

- [Solady](https://github.com/vectorized/solady)
- [MakerDao's Multicall](https://github.com/makerdao/multicall)

This project is a public good initiative of [sound.xyz](https://sound.xyz) and Solady.

We would like to thank our [reviewers and contributors](credits.txt) for their invaluable help.

[npm-shield]: https://img.shields.io/npm/v/multicaller.svg
[npm-url]: https://www.npmjs.com/package/multicaller

[ci-shield]: https://img.shields.io/github/actions/workflow/status/vectorized/multicaller/ci.yml?label=build&branch=main
[ci-url]: https://github.com/vectorized/multicaller/actions/workflows/ci.yml

[license-shield]: https://img.shields.io/badge/License-MIT-green.svg
[license-url]: https://github.com/vectorized/multicaller/blob/main/LICENSE.txt
 
