Original at: https://gist.github.com/0xPhaze/911518718a8c69d345954f8096d2c598

# General

No major vulnerabilities were identified.

# Scope

Review for [Vectorized/multicaller commit 0d5cb01](https://github.com/Vectorized/multicaller/commit/0d5cb01764404f94bf237459ef41cff1aa391fb2)

```
src
├── LibMulticaller.sol
├── Multicaller.sol
├── MulticallerSolidity.sol
├── MulticallerWithSender.sol
└── MulticallerWithSigner.sol
```

# Developer Integration Notes

Some developer integration notes and considerations could be further highlighted in the documentation.

- Leftover Ether resting in the Multicaller contracts is claimable by anyone.
- Multicalls are atomic: any revert in one of the calls reverts the entire transaction.
- Multicall contracts do not enforce a minimum gas amount for calls.
- Make sure the Multicall contracts are deployed for your chain.
- Multicall contracts should not be trusted with token approvals.
- Multicall allows receiving Ether without any functionality.
- Multicall provides a `refundTo` address to which any leftover Ether is sent after a multicall is performed. MulticallerWithSender and MulticallerWithSigner do not have this option and must ensure correct accounting.
- The call to `refundTo` is made with `100_000` gas, if this fails, a forced transfer via `selfdestruct`/`sendall` is made
- The Multicall contracts do not respect Solidity's memory model, however, this is not an issue if they remain self-contained external functions

# Notable Multicaller contract differences

|                                                                    Contract                                                                    | Provides secured `sender`/`signer` | Calldata compression | Refund address |
| :--------------------------------------------------------------------------------------------------------------------------------------------: | :--------------------------------: | :------------------: | :------------: |
|           [Multicaller](https://github.com/Vectorized/multicaller/blob/0d5cb01764404f94bf237459ef41cff1aa391fb2/src/Multicaller.sol)           |                 NO                 |         YES          |      YES       |
| [MulticallerWithSender](https://github.com/Vectorized/multicaller/blob/0d5cb01764404f94bf237459ef41cff1aa391fb2/src/MulticallerWithSender.sol) |                YES                 |          NO          |       NO       |
| [MulticallerWithSigner](https://github.com/Vectorized/multicaller/blob/0d5cb01764404f94bf237459ef41cff1aa391fb2/src/MulticallerWithSigner.sol) |                YES                 |          NO          |       NO       |

- Multicaller's usability is restricted to general calls that do not require special access control, as it does not provide a guarded `sender` to the target contract which could be used for access control checks
- If access control is required, this could be achieved via `tx.origin` checks, however these are generally discouraged due to phishing attacks
- Calldata compression is only added to Multicaller, as the others have already been deployed in production
- The `refundTo` address was not deemed necessary or added too late (further clarification required?)

---

### Cross-contract "re-entrancy" could break security assumptions when relying on `LibMulticaller.senderOrSigner`

**Severity:** Undetermined
**Likelihood:** Low
**Files:**
[LibMulticaller](src/LibMulticaller.sol),
[MulticallerWithSender](https://github.com/Vectorized/multicaller/blob/0d5cb01764404f94bf237459ef41cff1aa391fb2/src/MulticallerWithSender.sol),
[MulticallerWithSigner](https://github.com/Vectorized/multicaller/blob/0d5cb01764404f94bf237459ef41cff1aa391fb2/src/MulticallerWithSigner.sol)

`MulticallerWithSender` and `MulticallerWithSigner` contain re-entrancy guards to protect the `sender`/`signer` variable. These disallow re-entering the Multicall contracts that were initially called, however the re-entrancy guards do not apply to both contracts at the same time potentially allowing calls to re-enter the contract using `LibMulticaller.senderOrSigner` through the other Multicall contract. The affected contract might operate under the assumption that the `sender`/`signer` variables cannot equal the currently executing contract.

_Note:_ Any example scenarios of a contract relying on the assumption that the Multicaller contract cannot be re-entered for security purposes seem very unlikely.

**Exploit Scenario:**
A governance contract is responsible for maintaining and upgrading a bridge contract. Arbitrary calls can be executed immediately from a team controlled vault and admin account which is only allowed to call `MulticallerWithSigner` in order to batch process calls. Any critical operations directed towards the governance contract itself or the bridge contract are forbidden for the admin (`require(target != governance && target != bridge)`). These require an on-chain vote and a 7 day time delay to pass, allowing users to withdraw their funds before the proposals pass. After the 7 days, anyone can execute the call from the timelock contract which is routed through the governance contract allowing unconstrained calls. The governance contract checks access control via `LibMulticaller.senderOrSigner()`.

A rogue team member sends a transaction from the admin vault to `MulticallerWithSigner` which, in turn, calls the governance contract (`LibMulticaller.senderOrSigner() == admin`). The call then calls `MulticallerWithSender`, which then calls back into the governance contract (`LibMulticaller.senderOrSigner() == governance`). This is possible because the re-entrancy lock does not apply to both contracts at once. The call then upgrades the bridge contract to allow the rogue team member to withdraw all the locked funds bypassing the 7 day time window.

**Mitigation:**
Consider combining the logic of `MulticallerWithSender` and `MulticallerWithSigner` into one contract. Alternatively (not recommended), when retrieving the `sender`/`signer` from the Multicall contracts, check the re-entrancy guard of the other. At a minimum, highlight in the documentation that additional re-entrancy guards should be considered for developers when checking access via `LibMulticaller.senderOrSigner` or recommend that only one or the other (`sender` xor `signer`) should be used for contracts with complex access control requirements.

**Response:**

> We will make a comment that `LibMulticaller.senderOrSigner` does not offer re-entrancy protection.
> Users should add an re-entrancy guard on functions using `LibMulticaller.senderOrSigner`, if necessary.

---

### Decompress method differs from `LibZip.cdDecompress`

**Severity:** Low
**Likelihood:** Low
**Files:** [Multicaller](https://github.com/Vectorized/multicaller/blob/0d5cb01764404f94bf237459ef41cff1aa391fb2/src/Multicaller.sol),

`LibZip.cdDecompress` differs slightly from the way calldata is decompressed in Multicaller's fallback function. The Javascript implementation will decompress a run-length encoded value `0x00ff` as the byte `0xff` repeated `128` (`0x80 = 0x7f & 0xff + 0x01`) times. The Solidity implementation will decode `0x00ff` as `0xff` repeated `32` (`0x20`) times followed by `96` (`0x60`) zero bytes `0x00`.

[solady.js](https://github.com/Vectorized/solady/blob/ecee8d989eb869420a4ddfc82155531c8cc2b809/js/solady.js#L184C1-L206C6)

```js
/**
 * Decompresses hex encoded calldata.
 * @param {string} data A hex encoded string representing the compressed data.
 * @returns {string} The decompressed result as a hex encoded string.
 */
LibZip.cdDecompress = function (data) {
  data = hexString(data);
  var o = "0x",
    i = 0,
    c,
    s;

  while (i < data.length) {
    c = ((i < 4 * 2) * 0xff) ^ parseByte(data, i);
    i += 2;
    if (!c) {
      c = ((i < 4 * 2) * 0xff) ^ parseByte(data, i);
      s = (c & 0x7f) + 1;
      i += 2;
      while (s--) o += byteToString((c >> 7) * 0xff);
      continue;
    }
    o += byteToString(c);
  }
  return o;
};
```

This is not an issue for data encoded via `LibZip.cdCompress`, as the maximum length (`32`) of `0xff` bytes is handled correctly and only applies to compressed calldata which has been formed deliberately.

[solady.js](https://github.com/Vectorized/solady/blob/ecee8d989eb869420a4ddfc82155531c8cc2b809/js/solady.js#L165C1-L174C14)

```js
    if (!c) {
        if (y) rle(1, y), y = 0;
        if (++z === 0x80) rle(0, 0x80), z = 0;
        continue;
    }
    if (c === 0xff) {
        if (z) rle(0, z), z = 0;
        if (++y === 0x20) rle(1, 0x20), y = 0;
        continue;
    }
```

However, this could mean that front-end applications might not display the decoded calldata correctly in such a scenario where it is crafted by hand.

**Exploit Scenario:**
In a future where calldata compression is extended to be included in `MulicallerWithSender`, it is conceivable that some multisig or governance contracts might integrate `MulticallerWithSender` and `solady.js`. A malicious actor could then propose a transaction with hand crafted values hiding its true intentions. For example, a front-end application using `solady.js` would
decode the compressed calldata `0xff80` as `0xffffff... 0xffffff... 0xffffff...`, whereas, the actual calldata executed on-chain will end up being `0xffffff... 0x000000... 0x000000...`.

**Response:**
Acknowledged and fixed in [PR 559](https://github.com/Vectorized/solady/pull/559/files).

### `aggregateWithSigner` allows control over forwarded gas

**Severity:** Low
**Likelihood:** Low
**Files:** [MulticallerWithSigner](https://github.com/Vectorized/multicaller/blob/0d5cb01764404f94bf237459ef41cff1aa391fb2/src/MulticallerWithSigner.sol)

`MulticallerWithSigner`'s `aggregateWithSigner` function can be executed by anyone given a valid signature. The Multicall contracts do not enforce a minimum required amount of gas to be supplied with the calls. This opens up the ability for another user to control the forwarded gas amount. Some smart contracts define different behavior depending on the available gas. Examples are messaging protocols that include try-catch statements and store failed messages to be re-executed later. Combined with other protocols that require a certain minimum amount of gas to be forwarded (or with the 63/64 rule for transactions that use a lot of gas), this could allow another user to control the execution flow by front-running a transaction and modifying the `tx.gas` value.

**Exploit Scenario:**
A messaging protocol integrates `MulticallerWithSigner` Eve, a malicious actor, front-runs a transaction and is able to override the supplied gas values. This changes the transactions execution behavior.

**Mitigation:**
Consider including `uint256 gas` as a parameter (part of the signature) to ensure a necessary minimum amount of gas is available

**Response:**

> This is a limitation with the current approach we are willing to accept.

<!-- ### Unexpected Ether claim could result in subsequent call failure

**Severity:** Low
**Likelihood:** Low
**Files:**
[Multicaller](https://github.com/Vectorized/multicaller/blob/0d5cb01764404f94bf237459ef41cff1aa391fb2/src/Multicaller.sol),
[MulticallerWithSender](https://github.com/Vectorized/multicaller/blob/0d5cb01764404f94bf237459ef41cff1aa391fb2/src/MulticallerWithSender.sol),
[MulticallerWithSigner](https://github.com/Vectorized/multicaller/blob/0d5cb01764404f94bf237459ef41cff1aa391fb2/src/MulticallerWithSigner.sol)

A end-user of a dapp integrating Multicaller might set tight gas limits for their transaction. It is possible that effective gas costs for a transaction making it on-chain might differ from its simulated gas costs. This is because Multicaller allows Ether to rest in the contract and allows it to be claimed by anyone. A transaction that simulates the gas costs when the Multicaller contract contains Ether will estimate a lower gas requirement compared to when the contract's balance is zero.
This could result in a transaction failure due to out-of-gas.

**Mitigation:**
Consider requiring a minimum of 1 wei to rest in the contract. This could be included when deploying the contract.

**Response:** -->

---

### Missing implementation for `LibMulticaller.signer()`

**Severity:** Informational
**Files:** [LibMulticaller](src/LibMulticaller.sol)

`LibMulticaller` does not contain a method for retrieving the `signer` from `MulticallerWithSigner` without optionally allowing the `sender` from `MulticallerWithSender` to be retrieved instead.
This functionality could be important when considering the issue related to cross-contract re-entrancy.

**Mitigation:**

Include

```solidity
    /**
     * @dev Returns the signer of `aggregateWithSigner` on `MULTICALLER_WITH_SIGNER`,
     *      if the current context's `msg.sender` is `MULTICALLER_WITH_SIGNER`.
     *      Otherwise, returns `msg.sender`.
     */
    function signer() internal view returns (address result) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, caller())
            let withSigner := MULTICALLER_WITH_SIGNER
            if eq(caller(), withSigner) {
                if iszero(staticcall(gas(), withSigner, 0x00, 0x00, 0x00, 0x20)) {
                    revert(0x00, 0x00) // For better gas estimation.
                }
            }
            result := mload(0x00)
        }
    }
```

**Response:**

> May be good to add.

### `multicallerSender()` could be misunderstood

**Severity:** Informational
**Files:** [LibMulticaller](src/LibMulticaller.sol)

An app that integrates the `MulticallerWithSender` and `MulticallerWithSigner` contracts might end up using `LibMulticaller.multicallerSender()` even though they would like to integrate both contracts, not knowing that `multicallerSender` does not work for `MulticallerWithSigner`.

They might not include sufficient tests after testing with `MulticallerWithSender` and expect `MulticallerWithSigner` to work as well.

**Mitigation:**
Highlight in the documentation that `multicallerSender()` and `multicallerSigner()` can only be used for their respective separate contracts. The functionality of both contracts could be merged into one.

### "Forwarding `msg.sender`" might be misleading

**Severity:** Informational
**Files:** [LibMulticaller](src/LibMulticaller.sol)

The documentation mentions that `MulticallerWithSender` and `MulticallerWithSigner` "forward" `msg.sender`. This might be misleading, as the Multicaller's `msg.sender` is not forwarded as it is with [EIP-2771](https://eips.ethereum.org/EIPS/eip-2771),
where the `msg.sender` information is appended and retrieved via calldata of the current context. `LibMulticaller` instead requires external calls to the Multicaller contracts to be made. This information could be highlighted to allow developers to optimize their code by caching `LibMulticaller.sender` instead of repeatedly calling the function.

## Consider removing `receive()` for `Multicaller`

**Severity:** Informational
**Files:** [Multicaller](https://github.com/Vectorized/multicaller/blob/0d5cb01764404f94bf237459ef41cff1aa391fb2/src/Multicaller.sol)

The `Multicaller` contract is able to accept Ether, however there does not seem to be a clear use-case for allowing this.
Calling `Multicaller` with value and no data should be unintended as anyone is able to claim Ether in the contract. Consider removing the `receive()` function for `Multicaller`.

---

## Further Considerations

Consider adapting [EIP-4337's semi-abstracted nonces](https://eips.ethereum.org/EIPS/eip-4337#semi-abstracted-nonce-support). These allow for either sequential or unordered nonces, however, these come at the cost of increased complexity.

# Code Quality Recommendations

## Use early return pattern to avoid nested if conditions

```solidity
if data.length {
    // ...
}
```

This increases readability.

**Response:**

> This is intentional for reducing bytecode size in the case of the Multicaller.

## Declare arbitrary bytes as named constants

The selector of `error ArrayLengthsMismatch()` could be declared as a named constant `uint256 constant _SELECTOR_ARRAY_LENGTHS_MISMATCH = 0x3b800a46;`The same could be done for other constant byte selectors, e.g. `error InvalidSignature()`, or `name` in `eip712Domain`: `mstore(0xf5, 0x154d756c746963616c6c6572576974685369676e6572)`.

# Testing recommendations

## Include differential tests testing Yul against Solidity implementations

Consider writing the Multicaller contracts in Solidity. Differential tests can help discover discrepancies in functionality and can improve auditability by making these more accessible to a wider audience.

## Tests might be run against old version of Multicaller

The `setUp` script creates the various `Multicaller` contracts given hardcoded `bytes` values.

https://github.com/Vectorized/multicaller/blob/0d5cb01764404f94bf237459ef41cff1aa391fb2/test/Multicaller.t.sol#L153-L160

```solidity
    bytes public constant MULTICALLER_INITCODE = hex"6080806...";

    function setUp() public virtual {
        {
            bytes32 salt = MULTICALLER_CREATE2_SALT;
            bytes memory initcode = MULTICALLER_INITCODE;
            address expectedDeployment = MULTICALLER_CREATE2_DEPLOYED_ADDRESS;
            multicaller = Multicaller(payable(_safeCreate2(salt, initcode)));
            assertEq(address(multicaller), expectedDeployment);
        }

        // ...
```

Modifications made to the source code will not be reflected in the tests and errors might be overlooked. To ensure that the tests are run against the latest version of the code consider retrieving the latest creation code from the source.

```solidity
bytes public constant MULTICALLER_INITCODE = type(Multicaller).creationCode;
```

## Include test for `error ArrayLengthsMismatch()` selector

```solidity
    function testArrayLengthsMismatch(
        address[] calldata targets,
        bytes[] calldata data,
        uint256[] calldata values
    ) public {
        vm.assume(targets.length != data.length || targets.length != values.length);

        vm.expectRevert(ArrayLengthsMismatch.selector);
        multicaller.aggregate(targets, data, values, address(fallbackTargetA));
    }
```

## Consider replacing `vm.expectRevert()` with `vm.expectRevert(bytes(""))`

`vm.expectRevert()` catches any possible reverts. When specifically a revert with empty bytes is expected, `vm.expectRevert(bytes(""))` can be used.

# Optimizations

## `codecopy` could be unnecessary

**Files:** [Multicaller](https://github.com/Vectorized/multicaller/blob/0d5cb01764404f94bf237459ef41cff1aa391fb2/src/Multicaller.sol)

Assuming that memory is initialized to zero for a new call context, using `codecopy` could be unnecessary.

**Before:**

```solidity
// Fill with either 0xff or 0x00.
mstore(o, not(returndatasize()))
if iszero(gt(d, 0x7f)) { codecopy(o, codesize(), add(d, 1)) }
o := add(o, add(and(d, 0x7f), 1))
```

**After:**

```solidity
// Fill with either 0xff or 0x00.
mstore(o, mul(not(returndatasize()), gt(d, 0x7f))
// if iszero(gt(d, 0x7f)) { codecopy(o, codesize(), add(d, 1)) }
o := add(o, add(and(d, 0x7f), 1))
```

## Using `jumpi` could be cheaper

**Files:** [Multicaller](https://github.com/Vectorized/multicaller/blob/0d5cb01764404f94bf237459ef41cff1aa391fb2/src/Multicaller.sol)

**Before:**

```solidity
// If `refundTo` is `address(1)`, replace it with the `msg.sender`.
refundTo := xor(refundTo, mul(eq(refundTo, 1), xor(refundTo, caller())))
```

**After:**

```solidity
// If `refundTo` is `address(1)`, replace it with the `msg.sender`.
// refundTo := xor(refundTo, mul(eq(refundTo, 1), xor(refundTo, caller())))
if eq(refundTo, 1) { refundTo := caller() }
```

## `shr` instead of `shl` + `and`

**Files:** [MulticallerWithSender](https://github.com/Vectorized/multicaller/blob/0d5cb01764404f94bf237459ef41cff1aa391fb2/src/MulticallerWithSender.sol)

**Before:**

```solidity
if iszero(and(sload(returndatasize()), shl(160, 1))) {
    // ...
}
```

**After:**

```solidity
// if iszero(and(sload(returndatasize()), shl(160, 1))) {
if iszero(shr(160, sload(returndatasize()))) {
    // ...
}
```

## Use `eq` instead of `iszero(lt(...))`

**Files:** [MulticallerWithSender](https://github.com/Vectorized/multicaller/blob/0d5cb01764404f94bf237459ef41cff1aa391fb2/src/MulticallerWithSender.sol)

**Before:**

```solidity
if iszero(lt(results, data.length)) { break }
```

**After:**

```solidity
// if iszero(lt(results, data.length)) { break }
if eq(results, data.length) { break }
```
