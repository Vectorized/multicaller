# API

## Multicaller

### Functions

#### `aggregate`
```solidity
function aggregate(
    address[] calldata targets,
    bytes[] calldata data,
    uint256[] calldata values,
    address refundTo
) external payable returns (bytes[] memory)
```  
Aggregates multiple calls in a single transaction.

Remaining ETH in the contract after the calls can be refunded:
- If `refundTo` is `address(0)`, remaining ETH will NOT be refunded.
- If `refundTo` is `address(1)`, remaining ETH will be refunded to `msg.sender`.
- If `refundTo` is anything else, remaining ETH will be refunded to `refundTo`.

Returns an array of the returndata from each call.

#### `receive`
```solidity
receive() external payable
```

For receiving ETH.

Does nothing and returns nothing.

Will be called instead of `fallback()` if the calldatasize is zero.

#### `fallback`
```solidity
fallback() external payable
```

Decompresses the calldata and performs a delegatecall with the decompressed calldata to itself.

Accompanying JavaScript library to compress the calldata:  
https://github.com/vectorized/solady/blob/main/js/solady.js  
(See: `LibZip.cdCompress`)

## MulticallerWithSender

### Functions

#### `aggregateWithSender`
```solidity
function aggregateWithSender(
    address[] calldata targets, 
    bytes[] calldata data, 
    uint256[] calldata values
) external payable returns (bytes[] memory)
```  
Aggregates multiple calls in a single transaction.

This method will set the multicaller sender to the `msg.sender` temporarily for the span of its execution.

This method does NOT support reentrancy.

This method does NOT refund any excess ETH in the contract.

Returns an array of the returndata from each call.

#### `receive`
```solidity
receive() external payable
```  
Returns the caller of `aggregateWithSender` on the contract.

The value is always the zero address outside a transaction.

## MulticallerWithSigner

### Events

#### `NoncesInvalidated`
```solidity
event NoncesInvalidated(address indexed signer, uint256[] nonces)
```

Emitted when the `nonces` of `signer` are invalidated.

#### `NonceSaltIncremented`
```solidity
event NonceSaltIncremented(address indexed signer, uint256 newNonceSalt)
```

Emitted when the nonce salt of `signer` is incremented.

### Constants

These EIP-712 constants are made private to save function dispatch gas.  

If you need them in your code, please copy and paste them.

#### `_AGGREGATE_WITH_SIGNER_TYPEHASH`
```solidity
bytes32 private constant _AGGREGATE_WITH_SIGNER_TYPEHASH =
    0xfb989fd34c8af81a76f18167f528fc7315f92cacc19a0e63215abd54633f8a28;
```

For EIP-712 signature digest calculation for the `aggregateWithSigner` function.

`keccak256("AggregateWithSigner(address signer,address[] targets,bytes[] data,uint256[] values,uint256 nonce,uint256 nonceSalt)")`.

- `signer`:    The signer of the signature.
- `targets`:   An array of addresses to call.
- `data`:      An array of calldata to forward to the targets.
- `values`:    How much ETH to forward to each target.
- `nonce`:     The nonce for the signature.
- `nonceSalt`: The current nonce salt of the signer.

#### `_INVALIDATE_NONCES_FOR_SIGNER_TYPEHASH`
```solidity
bytes32 private constant _INVALIDATE_NONCES_FOR_SIGNER_TYPEHASH =
    0x12b047058eea3df4085cdc159a103d9c100c4e78cfb7029cc39d02cb8b9e48f5;
```

For EIP-712 signature digest calculation for the `invalidateNoncesForSigner` function.

`keccak256("InvalidateNoncesForSigner(address signer,uint256[] nonces,uint256 nonceSalt)")`.

- `signer`:    The signer of the signature.
- `nonces`:    The array of nonces for the signer.
- `nonceSalt`: The current nonce salt of the signer.

#### `_INCREMENT_NONCE_SALT_FOR_SIGNER_TYPEHASH`
```solidity
bytes32 private constant _INCREMENT_NONCE_SALT_FOR_SIGNER_TYPEHASH =
    0xfa181078c7d1d4d369301511d3c5611e9367d0cebbf65eefdee9dfc75849c1d3;
```

For EIP-712 signature digest calculation for the `incrementNonceSaltForSigner` function.

`keccak256("IncrementNonceSaltForSigner(address signer,uint256 nonceSalt)")`.

- `signer`:    The signer of the signature.
- `nonceSalt`: The current nonce salt of the signer.

#### `_DOMAIN_TYPEHASH`
```solidity
bytes32 private constant _DOMAIN_TYPEHASH =
    0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;
```

For EIP-712 signature digest calculation.

`keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")`.

#### `_NAME_HASH`
```solidity
bytes32 private constant _NAME_HASH =
    0x301013e8a31863902646dc218ecd889c37491c2967a8104d5ff1cf42af0f9ea4;
```

For EIP-712 signature digest calculation.

`keccak256("MulticallerWithSigner")`.

#### `_VERSION_HASH`
```solidity
bytes32 private constant _VERSION_HASH =
    0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6;
```

For EIP-712 signature digest calculation.

`keccak256("1")`.


### Functions

#### `aggregateWithSigner`
```solidity
function aggregateWithSigner(
    address[] calldata targets,
    bytes[] calldata data,
    uint256[] calldata values,
    uint256 nonceSalt,
    address signer,
    bytes calldata signature
) external payable returns (bytes[] memory)
```  
Aggregates multiple calls in a single transaction.

This method will set the multicaller signer to the `signer` temporarily for the span of its execution.

This method does NOT support reentrancy.

This method does NOT refund any excess ETH in the contract.

Emits a `NoncesInvalidated(signer, [nonce])` event.

Returns an array of the returndata from each call.

#### `invalidateNonces`
```solidity
function invalidateNonces(uint256[] calldata nonces) external
```

Invalidates the `nonces` of `msg.sender`.

Emits a `NoncesInvalidated(msg.sender, nonces)` event.

#### `invalidateNoncesForSigner`
```solidity
function invalidateNoncesForSigner(
    uint256[] calldata nonces,
    address signer,
    bytes calldata signature
) external
```

Invalidates the `nonces` of `signer`.

Emits a `NoncesInvalidated(signer, nonces)` event.

#### `noncesInvalidated`
```solidity
function noncesInvalidated(address signer, uint256[] calldata nonces)
    external
    view
    returns (bool[] memory)
```

Returns whether each of the `nonces` of `signer` has been invalidated.

#### `incrementNonceSalt`
```solidity
function incrementNonceSalt() external returns (uint256)
```

Increments the nonce salt of `msg.sender`.

For making all unused signatures with the current nonce salt invalid.

Will NOT make invalidated nonces available for use.

Emits a `NonceSaltIncremented(msg.sender, newNonceSalt)` event.

Returns the new nonce salt.

#### `incrementNonceSaltForSigner`
```solidity
function incrementNonceSaltForSigner(
    address signer,
    bytes calldata signature
) external returns (uint256)
```

Increments the nonce salt of `signer`.

For making all unused signatures with the current nonce salt invalid.

Will NOT make invalidated nonces available for use.

Emits a `NonceSaltIncremented(signer, newNonceSalt)` event.

Returns the new nonce salt.

#### `nonceSaltOf`
```solidity
function nonceSaltOf(address signer) external view returns (uint256)
```

Returns the nonce salt of `signer`.

#### `eip712Domain`
```solidity
function eip712Domain()
    external
    view
    returns (
        bytes1 fields,
        string memory name,
        string memory version,
        uint256 chainId,
        address verifyingContract,
        bytes32 salt,
        uint256[] memory extensions
    )
```

Returns the EIP-712 domain information, as specified in [EIP-5267](https://eips.ethereum.org/EIPS/eip-5267).

- `fields`:            `hex"0f"` (`0b01111`).
- `name`:              `"MulticallerWithSigner"`.
- `version`:           `"1"`.
- `chainId`:           The chain ID which this contract is on.
- `verifyingContract`: `address(this)`, the address of this contract.
- `salt`:              `bytes32(0)` (not used).
- `extensions`:        `[]` (not used).

#### `receive`
```solidity
receive() external payable
```  
Returns the caller of `aggregateWithSigner` on the contract.

The value is always the zero address outside a transaction.


## LibMulticaller

Library to read the multicaller contracts.

### Constants

#### `MULTICALLER`
```solidity
address internal constant MULTICALLER =
    0x0000000000002Bdbf1Bf3279983603Ec279CC6dF;
```

The address of the multicaller contract.

#### `MULTICALLER_WITH_SENDER`
```solidity
address internal constant MULTICALLER_WITH_SENDER =
    0x00000000002Fd5Aeb385D324B580FCa7c83823A0;
```

The address of the multicaller with sender contract.

#### `MULTICALLER_WITH_SIGNER`
```solidity
address internal constant MULTICALLER_WITH_SIGNER =
    0x000000000000D9ECebf3C23529de49815Dac1c4c;
```

The address of the multicaller with signer contract.

### Functions

The functions in this library do NOT guard against reentrancy.

A single transaction can recurse through different Multicallers  
(e.g. `MulticallerWithSender -> contract -> MulticallerWithSigner -> contract`).

Think of these functions like `msg.sender`.

If your contract `C` can handle reentrancy safely with plain old `msg.sender` for any `A -> C -> B -> C`, you should be fine substituting `msg.sender` with these functions.

#### `multicallerSender`
```solidity
function multicallerSender() internal view returns (address)
```  
Returns the caller of `aggregateWithSender` on the multicaller with sender contract.


#### `multicallerSigner`
```solidity
function multicallerSigner() internal view returns (address)
```  
Returns the signer of `aggregateWithSigner` on the multicaller with signer contract.


#### `sender`
```solidity
function sender() internal view returns (address result)
```  
Returns the caller of `aggregateWithSender` on the multicaller with sender contract, if `msg.sender` is the multicaller with sender contract.

Otherwise, returns `msg.sender`.


#### `signer`
```solidity
function signer() internal view returns (address result)
```  
Returns the caller of `aggregateWithSigner` on the multicaller with signer contract, if `msg.sender` is the multicaller with signer contract.

Otherwise, returns `msg.sender`.


#### `senderOrSigner`
```solidity
function senderOrSigner() internal view returns (address result)
```  
Returns the caller of `aggregateWithSender` on the multicaller with sender contract, if `msg.sender` is the multicaller with sender contract.

Returns the signer of `aggregateWithSigner` on the multicaller with signer contract, if `msg.sender` is the multicaller with signer contract.

Otherwise, returns `msg.sender`.
