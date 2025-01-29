# Multicaller

[![NPM][npm-shield]][npm-url]
[![CI][ci-shield]][ci-url]
[![Solidity][solidity-shield]][solidity-ci-url]

Efficiently call multiple contracts in a single transaction.

Enables "forwarding" of `msg.sender` to the contracts called.

## Deployments

Please open an issue if you need help to deploy to an EVM chain of your choice.

- Ethereum 
  - Multicaller: [`0x0000000000002Bdbf1Bf3279983603Ec279CC6dF`](https://etherscan.io/address/0x0000000000002Bdbf1Bf3279983603Ec279CC6dF)
  - MulticallerWithSender: [`0x00000000002Fd5Aeb385D324B580FCa7c83823A0`](https://etherscan.io/address/0x00000000002Fd5Aeb385D324B580FCa7c83823A0)
  - MulticallerWithSigner: [`0x000000000000D9ECebf3C23529de49815Dac1c4c`](https://etherscan.io/address/0x000000000000D9ECebf3C23529de49815Dac1c4c)
- Goerli 
  - Multicaller: [`0x0000000000002Bdbf1Bf3279983603Ec279CC6dF`](https://goerli.etherscan.io/address/0x0000000000002Bdbf1Bf3279983603Ec279CC6dF)
  - MulticallerWithSender: [`0x00000000002Fd5Aeb385D324B580FCa7c83823A0`](https://goerli.etherscan.io/address/0x00000000002Fd5Aeb385D324B580FCa7c83823A0)
  - MulticallerWithSigner: [`0x000000000000D9ECebf3C23529de49815Dac1c4c`](https://goerli.etherscan.io/address/0x000000000000D9ECebf3C23529de49815Dac1c4c)
- Sepolia 
  - Multicaller: [`0x0000000000002Bdbf1Bf3279983603Ec279CC6dF`](https://sepolia.etherscan.io/address/0x0000000000002Bdbf1Bf3279983603Ec279CC6dF)
  - MulticallerWithSender: [`0x00000000002Fd5Aeb385D324B580FCa7c83823A0`](https://sepolia.etherscan.io/address/0x00000000002Fd5Aeb385D324B580FCa7c83823A0)
  - MulticallerWithSigner: [`0x000000000000D9ECebf3C23529de49815Dac1c4c`](https://sepolia.etherscan.io/address/0x000000000000D9ECebf3C23529de49815Dac1c4c)
- Holesky 
  - Multicaller: [`0x0000000000002Bdbf1Bf3279983603Ec279CC6dF`](https://holesky.etherscan.io/address/0x0000000000002Bdbf1Bf3279983603Ec279CC6dF)
  - MulticallerWithSender: [`0x00000000002Fd5Aeb385D324B580FCa7c83823A0`](https://holesky.etherscan.io/address/0x00000000002Fd5Aeb385D324B580FCa7c83823A0)
  - MulticallerWithSigner: [`0x000000000000D9ECebf3C23529de49815Dac1c4c`](https://holesky.etherscan.io/address/0x000000000000D9ECebf3C23529de49815Dac1c4c)
- Polygon 
  - Multicaller: [`0x0000000000002Bdbf1Bf3279983603Ec279CC6dF`](https://polygonscan.com/address/0x0000000000002Bdbf1Bf3279983603Ec279CC6dF)
  - MulticallerWithSender: [`0x00000000002Fd5Aeb385D324B580FCa7c83823A0`](https://polygonscan.com/address/0x00000000002Fd5Aeb385D324B580FCa7c83823A0)
  - MulticallerWithSigner: [`0x000000000000D9ECebf3C23529de49815Dac1c4c`](https://polygonscan.com/address/0x000000000000D9ECebf3C23529de49815Dac1c4c)
- Mumbai 
  - Multicaller: [`0x0000000000002Bdbf1Bf3279983603Ec279CC6dF`](https://mumbai.polygonscan.com/address/0x0000000000002Bdbf1Bf3279983603Ec279CC6dF)
  - MulticallerWithSender: [`0x00000000002Fd5Aeb385D324B580FCa7c83823A0`](https://mumbai.polygonscan.com/address/0x00000000002Fd5Aeb385D324B580FCa7c83823A0)
  - MulticallerWithSigner: [`0x000000000000D9ECebf3C23529de49815Dac1c4c`](https://mumbai.polygonscan.com/address/0x000000000000D9ECebf3C23529de49815Dac1c4c)
- Optimism 
  - Multicaller: [`0x0000000000002Bdbf1Bf3279983603Ec279CC6dF`](https://optimistic.etherscan.io/address/0x0000000000002Bdbf1Bf3279983603Ec279CC6dF)
  - MulticallerWithSender: [`0x00000000002Fd5Aeb385D324B580FCa7c83823A0`](https://optimistic.etherscan.io/address/0x00000000002Fd5Aeb385D324B580FCa7c83823A0)
  - MulticallerWithSigner: [`0x000000000000D9ECebf3C23529de49815Dac1c4c`](https://optimistic.etherscan.io/address/0x000000000000D9ECebf3C23529de49815Dac1c4c)
- Arbitrum 
  - Multicaller: [`0x0000000000002Bdbf1Bf3279983603Ec279CC6dF`](https://arbiscan.io/address/0x0000000000002Bdbf1Bf3279983603Ec279CC6dF)
  - MulticallerWithSender: [`0x00000000002Fd5Aeb385D324B580FCa7c83823A0`](https://arbiscan.io/address/0x00000000002Fd5Aeb385D324B580FCa7c83823A0)
  - MulticallerWithSigner: [`0x000000000000D9ECebf3C23529de49815Dac1c4c`](https://arbiscan.io/address/0x000000000000D9ECebf3C23529de49815Dac1c4c)
- Base
  - Multicaller: [`0x0000000000002Bdbf1Bf3279983603Ec279CC6dF`](https://basescan.org/address/0x0000000000002Bdbf1Bf3279983603Ec279CC6dF)
  - MulticallerWithSender: [`0x00000000002Fd5Aeb385D324B580FCa7c83823A0`](https://basescan.org/address/0x00000000002Fd5Aeb385D324B580FCa7c83823A0)
  - MulticallerWithSigner: [`0x000000000000D9ECebf3C23529de49815Dac1c4c`](https://basescan.org/address/0x000000000000D9ECebf3C23529de49815Dac1c4c)
- Blast
  - Multicaller: [`0x0000000000002Bdbf1Bf3279983603Ec279CC6dF`](https://blastscan.io/address/0x0000000000002Bdbf1Bf3279983603Ec279CC6dF)
  - MulticallerWithSender: [`0x00000000002Fd5Aeb385D324B580FCa7c83823A0`](https://blastscan.io/address/0x00000000002Fd5Aeb385D324B580FCa7c83823A0)
  - MulticallerWithSigner: [`0x000000000000D9ECebf3C23529de49815Dac1c4c`](https://blastscan.io/address/0x000000000000D9ECebf3C23529de49815Dac1c4c)

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

## Safety

We **do not give any warranties** and **will not be liable for any loss** incurred through any use of this codebase.

Please read the API docs / Natspec, test with your code, and get additional security reviews to make sure that any usage is done safely.

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

[solidity-shield]: https://img.shields.io/badge/solidity-%3E=0.8.10%20%3C=0.8.25-aa6746
[solidity-ci-url]: https://github.com/Vectorized/solady/actions/workflows/ci-all-via-ir.yml
