# Multicaller

[![NPM][npm-shield]][npm-url]
[![CI][ci-shield]][ci-url]
[![MIT License][license-shield]][license-url]

> **Warning**   
> This repository is still under heavy construction and review. Please do not use yet.

## Deployments

| Chain | Multicaller |
|---|---|
| Ethereum | [`0x00000000007CA48999F700f0Ac66A534062f73b1`](https://etherscan.io/address/0x00000000007CA48999F700f0Ac66A534062f73b1) |
| Goerli | [`0x00000000007CA48999F700f0Ac66A534062f73b1`](https://goerli.etherscan.io/address/0x00000000007CA48999F700f0Ac66A534062f73b1) |
| Polygon | [`0x00000000007CA48999F700f0Ac66A534062f73b1`](https://polygonscan.com/address/0x00000000007CA48999F700f0Ac66A534062f73b1) |
| Mumbai | [`0x00000000007CA48999F700f0Ac66A534062f73b1`](https://mumbai.polygonscan.com/address/0x00000000007CA48999F700f0Ac66A534062f73b1) |


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

## API

### `aggregate`
```solidity
function aggregate(address[] calldata targets, bytes[] calldata data)
    external
    payable
    returns (bytes[] memory)
```  
Aggregates multiple calls in a single transaction.

The `msg.value` will be forwarded to the starting call.

### `aggregateWithSender`
```solidity
function aggregateWithSender(address[] calldata targets, bytes[] calldata data)
    external
    payable
    returns (bytes[] memory)
```  
Aggregates multiple calls in a single transaction.

The `msg.value` will be forwarded to the starting call.

This method will set `sender` to the `msg.sender` temporarily for the span of its execution.

This method does not support reentrancy.

### `fallback`
```solidity
fallback() external payable
```  
Returns the address that called `aggregateWithSender` on the contract.

The value is always the zero address outside a transaction.

## Design

The contracts are designed with a priority on efficiency and minimalism. 

- Multiple input calldata arrays instead of an array of structs for more compact calldata encoding.

- Omission of utility functions like `getBlockNumber` for more efficient function dispatch. If you need those functions, just add those functions into your contract, or read them off a separate utility contract like [MakerDao's Multicall](https://github.com/makerdao/multicall).

## Safety

We **do not give any warranties** and **will not be liable for any loss** incurred through any use of this codebase.

## Acknowledgments

This repository is inspired by and directly modified from:

- [Solady](https://github.com/vectorized/solady)
- [MakerDao's Multicall](https://github.com/makerdao/multicall)


[npm-shield]: https://img.shields.io/npm/v/multicaller.svg
[npm-url]: https://www.npmjs.com/package/multicaller

[ci-shield]: https://img.shields.io/github/actions/workflow/status/vectorized/multicaller/ci.yml?label=build&branch=main
[ci-url]: https://github.com/vectorized/multicaller/actions/workflows/ci.yml

[license-shield]: https://img.shields.io/badge/License-MIT-green.svg
[license-url]: https://github.com/vectorized/multicaller/blob/main/LICENSE.txt
