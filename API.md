# API

## Multicaller

### Functions

#### `aggregate`
```solidity
function aggregate(
    address[] calldata targets,
    bytes[] calldata data,
    uint256[] calldata values
) external payable returns (bytes[] memory)
```  
Aggregates multiple calls in a single transaction.

Returns an array of the returndata from each call.

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

This method does not support reentrancy.

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

### Functions

#### `aggregateWithSigner`
```solidity
function aggregateWithSigner(
    string memory message,
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

This method does not support reentrancy.

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

- fields            `hex"0f"` (`0b01111`).
- name              `"MulticallerWithSender"`.
- version           `"1"`.
- chainId           The chain ID which this contract is on.
- verifyingContract `address(this)`, the address of this contract.
- salt              `bytes32(0)` (not used).
- extensions        `[]` (not used).

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
address internal constant MULTICALLER
```

The address of the multicaller contract.

#### `MULTICALLER_WITH_SENDER`
```solidity
address internal constant MULTICALLER_WITH_SENDER
```

The address of the multicaller with sender contract.

#### `MULTICALLER_WITH_SIGNER`
```solidity
address internal constant MULTICALLER_WITH_SIGNER
```

The address of the multicaller with signer contract.

### Functions

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

#### `senderOrSigner`
```solidity
function senderOrSigner() internal view returns (address result)
```  
Returns the caller of `aggregateWithSender` on the multicaller with sender contract, if `msg.sender` is the multicaller with sender contract.

Returns the signer of `aggregateWithSigner` on the multicaller with signer contract, if `msg.sender` is the multicaller with signer contract.

Otherwise, returns `msg.sender`.
