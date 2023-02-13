# Multicaller

[![NPM][npm-shield]][npm-url]
[![CI][ci-shield]][ci-url]
[![MIT License][license-shield]][license-url]


> **Warning**   
> This repository is still under heavy construction and review. Please do not use yet.

## Deployments

| Chain | Multicaller |
|---|---|
| Ethereum | [`0x000000000031d507607FfDd9230f3d28a269b0Eb`](https://etherscan.io/address/0x000000000031d507607FfDd9230f3d28a269b0Eb) |
| Goerli | [`0x000000000031d507607FfDd9230f3d28a269b0Eb`](https://goerli.etherscan.io/address/0x000000000031d507607FfDd9230f3d28a269b0Eb) |
| Polygon | [`0x000000000031d507607FfDd9230f3d28a269b0Eb`](https://polygonscan.com/address/0x000000000031d507607FfDd9230f3d28a269b0Eb) |
| Mumbai | [`0x000000000031d507607FfDd9230f3d28a269b0Eb`](https://mumbai.polygonscan.com/address/0x000000000031d507607FfDd9230f3d28a269b0Eb) |


Please open an issue if you need help to deploy to an EVM chain of your choice.

## Contracts

```ml
src
├─ Multicaller.sol — "The multicaller contract"
└─ MulticallerReader.sol — "Library to read the sender of the multicaller contract"
``` 

## Installation

You can use the [`src/MulticallerReader.sol`](./src/MulticallerReader.sol) library in your contracts to query the Multicaller efficiently.

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
