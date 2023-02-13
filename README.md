# Multicaller

[![NPM][npm-shield]][npm-url]
[![CI][ci-shield]][ci-url]
[![MIT License][license-shield]][license-url]


> **Warning**   
> This repository is still under heavy construction and review. Please do not use yet.

## Deployments

| Chain | Multicaller |
|---|---|
| Ethereum | [`0x0000000068B4AA007A36A318d9BcC64f8844F173`](https://etherscan.io/address/0x0000000068B4AA007A36A318d9BcC64f8844F173) |
| Goerli | [`0x0000000068B4AA007A36A318d9BcC64f8844F173`](https://goerli.etherscan.io/address/0x0000000068B4AA007A36A318d9BcC64f8844F173) |
| Polygon | [`0x0000000068B4AA007A36A318d9BcC64f8844F173`](https://polygonscan.com/address/0x0000000068B4AA007A36A318d9BcC64f8844F173) |
| Mumbai | [`0x0000000068B4AA007A36A318d9BcC64f8844F173`](https://mumbai.polygonscan.com/address/0x0000000068B4AA007A36A318d9BcC64f8844F173) |


Please open an issue if you need help to deploy to an EVM chain of your choice.

## Contracts

```ml
src
├─ Multicaller.sol — "The multicaller contract"
└─ MulticallerChecker.sol — "Library to check the sender of the multicaller contract"
``` 

## Installation

You can use the [`src/MulticallerChecker.sol`](./src/MulticallerChecker.sol) library in your contracts to query the Multicaller efficiently.

To install with [**Foundry**](https://github.com/gakonst/foundry):

```sh
forge install vectorized/multicaller
```

To install with [**Hardhat**](https://github.com/nomiclabs/hardhat) or [**Truffle**](https://github.com/trufflesuite/truffle):

```sh
npm install multicaller
```

## Safety

We **do not give any warranties** and **will not be liable for any loss** incurred through any use of this codebase.

## Acknowledgements

This repository is inspired by and directly modified from:

- [Solady](https://github.com/vectorized/solady)


[npm-shield]: https://img.shields.io/npm/v/multicaller.svg
[npm-url]: https://www.npmjs.com/package/multicaller

[ci-shield]: https://img.shields.io/github/actions/workflow/status/vectorized/multicaller/ci.yml?label=build&branch=main
[ci-url]: https://github.com/vectorized/multicaller/actions/workflows/ci.yml

[license-shield]: https://img.shields.io/badge/License-MIT-green.svg
[license-url]: https://github.com/vectorized/multicaller/blob/main/LICENSE.txt
