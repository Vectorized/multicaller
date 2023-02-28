# Multicaller

[![NPM][npm-shield]][npm-url]
[![CI][ci-shield]][ci-url]
[![MIT License][license-shield]][license-url]

Efficiently call multiple contracts in a single transaction.

Optionally "forwards" `msg.sender` to the contracts called.

## Deployments

| Chain | Multicaller | MulticallerWithSender |
|---|---|---|
| Ethereum | [`0x0000000000e00b934df5E876c6CbE7fDAfc253A6`](https://etherscan.io/address/0x0000000000e00b934df5E876c6CbE7fDAfc253A6) | [`0x00000000003248fcE45dFE3f5E1a15Eff24fD644`](https://etherscan.io/address/0x00000000003248fcE45dFE3f5E1a15Eff24fD644) |
| Goerli | [`0x0000000000e00b934df5E876c6CbE7fDAfc253A6`](https://goerli.etherscan.io/address/0x0000000000e00b934df5E876c6CbE7fDAfc253A6) | [`0x00000000003248fcE45dFE3f5E1a15Eff24fD644`](https://goerli.etherscan.io/address/0x00000000003248fcE45dFE3f5E1a15Eff24fD644) |
| Sepolia | [`0x0000000000e00b934df5E876c6CbE7fDAfc253A6`](https://sepolia.etherscan.io/address/0x0000000000e00b934df5E876c6CbE7fDAfc253A6) | [`0x00000000003248fcE45dFE3f5E1a15Eff24fD644`](https://sepolia.etherscan.io/address/0x00000000003248fcE45dFE3f5E1a15Eff24fD644) |
| Polygon | [`0x0000000000e00b934df5E876c6CbE7fDAfc253A6`](https://polygonscan.com/address/0x0000000000e00b934df5E876c6CbE7fDAfc253A6) | [`0x00000000003248fcE45dFE3f5E1a15Eff24fD644`](https://polygonscan.com/address/0x00000000003248fcE45dFE3f5E1a15Eff24fD644) |
| Mumbai | [`0x0000000000e00b934df5E876c6CbE7fDAfc253A6`](https://mumbai.polygonscan.com/address/0x0000000000e00b934df5E876c6CbE7fDAfc253A6) | [`0x00000000003248fcE45dFE3f5E1a15Eff24fD644`](https://mumbai.polygonscan.com/address/0x00000000003248fcE45dFE3f5E1a15Eff24fD644) |
| Optimism | [`0x0000000000e00b934df5E876c6CbE7fDAfc253A6`](https://optimistic.etherscan.io/address/0x0000000000e00b934df5E876c6CbE7fDAfc253A6) | [`0x00000000003248fcE45dFE3f5E1a15Eff24fD644`](https://optimistic.etherscan.io/address/0x00000000003248fcE45dFE3f5E1a15Eff24fD644) |
| Arbitrum | [`0x0000000000e00b934df5E876c6CbE7fDAfc253A6`](https://arbiscan.io/address/0x0000000000e00b934df5E876c6CbE7fDAfc253A6) | [`0x00000000003248fcE45dFE3f5E1a15Eff24fD644`](https://arbiscan.io/address/0x00000000003248fcE45dFE3f5E1a15Eff24fD644) |

Please open an issue if you need help to deploy to an EVM chain of your choice.

## Contracts

```ml
src
├─ Multicaller.sol — "The multicaller contract"
├─ MulticallerWithSender.sol — "The multicaller with sender contract"
└─ LibMulticaller.sol — "Library to read the multicaller with sender contract"
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

### Multicaller

#### `aggregate`
```solidity
function aggregate(address[] calldata targets, bytes[] calldata data)
    external
    payable
    returns (bytes[] memory)
```  
Aggregates multiple calls in a single transaction.

The `msg.value` will be forwarded to the last call.

### MulticallerWithSender

#### `aggregateWithSender`
```solidity
function aggregateWithSender(address[] calldata targets, bytes[] calldata data)
    external
    payable
    returns (bytes[] memory)
```  
Aggregates multiple calls in a single transaction.

The `msg.value` will be forwarded to the last call.

This method will set the multicaller sender to the `msg.sender` temporarily for the span of its execution.

This method does not support reentrancy.

#### `fallback`
```solidity
fallback() external payable
```  
Returns the address that called `aggregateWithSender` on the contract.

The value is always the zero address outside a transaction.

### LibMulticaller

Library to read the multicaller with sender contract.

#### `multicallerSender`
```solidity
function multicallerSender() internal view returns (address)
```  
Returns the address that called `aggregateWithSender` on the multicaller with sender contract.

#### `sender`
```solidity
function sender() internal view returns (address result)
```  
Returns the address that called `aggregateWithSender` on the multicaller with sender contract, if `msg.sender` is the multicaller with sender contract.

Otherwise, returns `msg.sender`.

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
 
