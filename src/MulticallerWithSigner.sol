// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/**
 * @title MulticallerWithSigner
 * @author vectorized.eth
 * @notice Contract that allows for efficient aggregation of multiple calls
 *         in a single transaction, while "forwarding" the `signer`.
 */
contract MulticallerWithSigner {
    // =============================================================
    //                            EVENTS
    // =============================================================

    /**
     * @dev Emitted when the `nonces` of `signer` are invalidated.
     * @param signer The signer of the signature.
     * @param nonces The array of nonces invalidated.
     */
    event NoncesInvalidated(address indexed signer, uint256[] nonces);

    /**
     * @dev Emitted when the nonce salt of `signer` is incremented.
     * @param signer       The signer of the signature.
     * @param newNonceSalt The new nonce salt.
     */
    event NonceSaltIncremented(address indexed signer, uint256 newNonceSalt);

    /**
     * @dev `keccak256("NoncesInvalidated(address,uint256[])")`.
     */
    uint256 private constant _NONCES_INVALIDATED_EVENT_SIGNATURE =
        0xc45e3a0dd412bcad8d62398d74d66b1c8449f38beb10da275e4da0c6d3a811a4;

    /**
     * @dev `keccak256("NonceSaltIncremented(address,uint256)")`.
     */
    uint256 private constant _NONCE_SALT_INCREMENTED_EVENT_SIGNATURE =
        0x997a42216df16c8b9e7caf2fc71c59dba956f1f2b12320f87a80a5879464217d;

    // =============================================================
    //                           CONSTANTS
    // =============================================================

    // These EIP-712 constants are made private to save function dispatch gas.
    // If you need them in your code, please copy and paste them.

    /**
     * @dev For EIP-712 signature digest calculation for the
     *      `aggregateWithSigner` function.
     *      `keccak256("AggregateWithSigner(address signer,address[] targets,bytes[] data,uint256[] values,uint256 nonce,uint256 nonceSalt)")`.
     */
    bytes32 private constant _AGGREGATE_WITH_SIGNER_TYPEHASH =
        0xfb989fd34c8af81a76f18167f528fc7315f92cacc19a0e63215abd54633f8a28;

    /**
     * @dev For EIP-712 signature digest calculation for the
     *      `invalidateNoncesForSigner` function.
     *      `keccak256("InvalidateNoncesForSigner(address signer,uint256[] nonces,uint256 nonceSalt)")`.
     */
    bytes32 private constant _INVALIDATE_NONCES_FOR_SIGNER_TYPEHASH =
        0x12b047058eea3df4085cdc159a103d9c100c4e78cfb7029cc39d02cb8b9e48f5;

    /**
     * @dev For EIP-712 signature digest calculation for the
     *      `incrementNonceSaltForSigner` function.
     *      `keccak256("IncrementNonceSaltForSigner(address signer,uint256 nonceSalt)")`.
     */
    bytes32 private constant _INCREMENT_NONCE_SALT_FOR_SIGNER_TYPEHASH =
        0xfa181078c7d1d4d369301511d3c5611e9367d0cebbf65eefdee9dfc75849c1d3;

    /**
     * @dev For EIP-712 signature digest calculation.
     *      `keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")`.
     */
    bytes32 private constant _DOMAIN_TYPEHASH =
        0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

    /**
     * @dev For EIP-712 signature digest calculation.
     *      `keccak256("MulticallerWithSigner")`.
     */
    bytes32 private constant _NAME_HASH =
        0x301013e8a31863902646dc218ecd889c37491c2967a8104d5ff1cf42af0f9ea4;

    /**
     * @dev For EIP-712 signature digest calculation.
     *      `keccak256("1")`.
     */
    bytes32 private constant _VERSION_HASH =
        0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6;

    // =============================================================
    //                            ERRORS
    // =============================================================

    /**
     * @dev The lengths of the input arrays are not the same.
     */
    error ArrayLengthsMismatch();

    /**
     * @dev This function does not support reentrancy.
     */
    error Reentrancy();

    /**
     * @dev The signature is invalid: it must be correctly signed by the signer,
     *      with the correct data, an unused nonce, and the signer's current nonce salt.
     */
    error InvalidSignature();

    // =============================================================
    //                          CONSTRUCTOR
    // =============================================================

    constructor() payable {
        assembly {
            // Throughout this code, we will abuse returndatasize
            // in place of zero anywhere before a call to save a bit of gas.
            // We will use storage slot zero to store the signer at
            // bits [96..255] and reentrancy guard at bit 1.
            sstore(returndatasize(), 1)
        }
    }

    // =============================================================
    //                    AGGREGATION OPERATIONS
    // =============================================================

    /**
     * @dev Returns the signer passed into `aggregateWithSigner` on this contract.
     *      The value is always the zero address outside a transaction.
     */
    receive() external payable {
        assembly {
            mstore(0x0c, sload(returndatasize()))
            return(returndatasize(), 0x20)
        }
    }

    /**
     * @dev Aggregates multiple calls in a single transaction.
     *      This method will store the `signer` temporarily
     *      for the span of its execution.
     *      This method does not support reentrancy.
     *      Emits a `NoncesInvalidated(signer, [nonce])` event.
     * @param targets   An array of addresses to call.
     * @param data      An array of calldata to forward to the targets.
     * @param values    How much ETH to forward to each target.
     * @param nonce     The nonce for the signature.
     * @param signer    The signer of the signature.
     * @param signature The signature by the signer.
     * @return An array of the returndata from each call.
     */
    function aggregateWithSigner(
        address[] calldata targets,
        bytes[] calldata data,
        uint256[] calldata values,
        uint256 nonce,
        address signer,
        bytes calldata signature
    ) external payable returns (bytes[] memory) {
        assembly {
            if iszero(and(eq(targets.length, data.length), eq(data.length, values.length))) {
                mstore(returndatasize(), 0x3b800a46) // `ArrayLengthsMismatch()`.
                revert(0x1c, 0x04)
            }

            if iszero(and(1, sload(returndatasize()))) {
                mstore(returndatasize(), 0xab143c06) // `Reentrancy()`.
                revert(0x1c, 0x04)
            }

            // Multiply `data.length` by 0x20 to give the byte length of the `data` offsets array.
            // This is the also the byte length of the `targets` array and `values` array.
            data.length := shl(5, data.length)

            /* -------------------- CHECK SIGNATURE --------------------- */

            // Compute `keccak256(abi.encodePacked(values))`.
            calldatacopy(returndatasize(), values.offset, data.length)
            let valuesHash := keccak256(returndatasize(), data.length)
            // Compute `keccak256(abi.encodePacked(keccak256(data[0]), ..))`.
            for { let i := returndatasize() } iszero(eq(i, data.length)) { i := add(i, 0x20) } {
                let o := add(data.offset, calldataload(add(data.offset, i)))
                calldatacopy(i, add(o, 0x20), calldataload(o))
                mstore(i, keccak256(i, calldataload(o)))
            }
            let dataHash := keccak256(returndatasize(), data.length)
            // Compute `keccak256(abi.encodePacked(targets))`.
            calldatacopy(returndatasize(), targets.offset, data.length)
            let targetsHash := keccak256(returndatasize(), data.length)

            // Layout the fields of the struct hash.
            mstore(returndatasize(), _AGGREGATE_WITH_SIGNER_TYPEHASH)
            mstore(0x20, signer)
            mstore(0x40, targetsHash)
            mstore(0x60, dataHash)
            mstore(0x80, valuesHash)
            mstore(0xa0, nonce)
            mstore(0xc0, sload(add(signer, address()))) // Store the nonce salt.
            mstore(0x40, keccak256(returndatasize(), 0xe0)) // Compute and store the struct hash.
            // Layout the fields of the domain separator.
            mstore(0x60, _DOMAIN_TYPEHASH)
            mstore(0x80, _NAME_HASH)
            mstore(0xa0, _VERSION_HASH)
            mstore(0xc0, chainid())
            mstore(0xe0, address())
            mstore(0x20, keccak256(0x60, 0xa0)) // Compute and store the domain separator.
            // Layout the fields of `ecrecover`.
            mstore(returndatasize(), 0x1901) // Store "\x19\x01".
            let digest := keccak256(0x1e, 0x42) // Compute the digest.
            for {} 1 {} {
                if eq(signature.length, 64) {
                    mstore(returndatasize(), digest) // Store the digest.
                    let vs := calldataload(add(signature.offset, 0x20))
                    mstore(0x20, add(shr(255, vs), 27)) // `v`.
                    mstore(0x40, calldataload(signature.offset)) // `r`.
                    mstore(0x60, shr(1, shl(1, vs))) // `s`.
                    let t := staticcall(gas(), 1, 0x00, 0x80, 0x01, 0x20)
                    if iszero(or(iszero(returndatasize()), xor(signer, mload(t)))) { break }
                }
                if eq(signature.length, 65) {
                    mstore(returndatasize(), digest) // Store the digest.
                    calldatacopy(0x40, signature.offset, signature.length) // Copy `r`, `s`, `v`.
                    mstore(0x20, byte(returndatasize(), mload(0x80))) // `v`.
                    let t := staticcall(gas(), 1, 0x00, 0x80, 0x01, 0x20)
                    if iszero(or(iszero(returndatasize()), xor(signer, mload(t)))) { break }
                }
                // ERC1271 fallback.
                let f := shl(224, 0x1626ba7e) // `isValidSignature(bytes32,bytes)`.
                mstore(0x00, f)
                mstore(0x04, digest)
                mstore(0x24, 0x40)
                mstore(0x44, signature.length)
                calldatacopy(0x64, signature.offset, signature.length)
                let t := staticcall(gas(), signer, 0x00, add(signature.length, 0x64), 0x24, 0x20)
                if iszero(and(eq(mload(0x24), f), t)) {
                    mstore(0x00, 0x8baa579f) // `InvalidSignature()`.
                    revert(0x1c, 0x04)
                }
                break
            }

            // Check the nonce.
            mstore(0x20, signer)
            mstore(0x40, nonce)
            let bucketSlot := keccak256(0x20, 0x3f)
            let bucketValue := sload(bucketSlot)
            let bit := shl(and(0xff, nonce), 1)
            if and(bit, bucketValue) {
                mstore(0x00, 0x8baa579f) // `InvalidSignature()`.
                revert(0x1c, 0x04)
            }
            sstore(bucketSlot, or(bucketValue, bit)) // Invalidate the nonce.

            // Emit `NoncesInvalidated(signer, [nonce])`.
            mstore(0x00, 0x20)
            mstore(0x20, 1)
            // The nonce is already at 0x40.
            log2(0x00, 0x60, _NONCES_INVALIDATED_EVENT_SIGNATURE, signer)

            /* ------------------- PERFORM AGGREGATE -------------------- */

            // Early return if no data.
            if iszero(data.length) {
                // Slot 0x00's value is already 0x20.
                mstore(0x20, data.length) // Store `data.length` into `results`.
                return(0x00, 0x40)
            }

            // Set the signer slot temporarily for the span of this transaction.
            sstore(0, shl(96, signer))

            let results := 0x40
            // Copy the offsets from calldata into memory.
            calldatacopy(results, data.offset, data.length)
            // Offset into `results`.
            let resultsOffset := data.length
            // Pointer to the end of `results`.
            let end := add(results, data.length)
            // For deriving the calldata offsets from the `results` pointer.
            let valuesOffsetDiff := sub(values.offset, results)
            let targetsOffsetDiff := sub(targets.offset, results)

            for {} 1 {} {
                // The offset of the current bytes in the calldata.
                let o := add(data.offset, mload(results))
                let memPtr := add(resultsOffset, 0x40)
                // Copy the current bytes from calldata to the memory.
                calldatacopy(
                    memPtr,
                    add(o, 0x20), // The offset of the current bytes' bytes.
                    calldataload(o) // The length of the current bytes.
                )
                if iszero(
                    call(
                        gas(), // Remaining gas.
                        calldataload(add(targetsOffsetDiff, results)), // Address to call.
                        calldataload(add(valuesOffsetDiff, results)), // ETH to send.
                        memPtr, // Start of input calldata in memory.
                        calldataload(o), // Size of input calldata.
                        0x00, // We will use returndatacopy instead.
                        0x00 // We will use returndatacopy instead.
                    )
                ) {
                    // Bubble up the revert if the call reverts.
                    returndatacopy(0x00, 0x00, returndatasize())
                    revert(0x00, returndatasize())
                }
                // Append the current `resultsOffset` into `results`.
                mstore(results, resultsOffset)
                // Append the returndatasize, and the returndata.
                mstore(memPtr, returndatasize())
                returndatacopy(add(memPtr, 0x20), 0x00, returndatasize())
                // Advance the `resultsOffset` by `returndatasize() + 0x20`,
                // rounded up to the next multiple of 0x20.
                resultsOffset := and(add(add(resultsOffset, returndatasize()), 0x3f), not(0x1f))
                // Advance the `results` pointer.
                results := add(results, 0x20)
                if eq(results, end) { break }
            }
            // Slot 0x00's value is already 0x20.
            mstore(0x20, targets.length) // Store `targets.length` into `results`.

            // Restore the `signer` slot.
            sstore(0, 1)
            // Direct return.
            return(0x00, add(resultsOffset, 0x40))
        }
    }

    // =============================================================
    //                     SIGNATURE OPERATIONS
    // =============================================================

    /**
     * @dev Invalidates the `nonces` of `msg.sender`.
     *      Emits a `NoncesInvalidated(msg.sender, nonces)` event.
     * @param nonces An array of nonces to invalidate.
     */
    function invalidateNonces(uint256[] calldata nonces) external {
        assembly {
            mstore(0x00, caller())
            // Iterate through all the nonces and set their boolean values in the storage.
            let end := shl(5, nonces.length)
            for { let i := 0 } iszero(eq(i, end)) { i := add(i, 0x20) } {
                let nonce := calldataload(add(nonces.offset, i))
                mstore(0x20, nonce)
                let bucketSlot := keccak256(0x00, 0x3f)
                sstore(bucketSlot, or(sload(bucketSlot), shl(and(0xff, nonce), 1)))
            }
            // Emit `NoncesInvalidated(msg.sender, nonces)`.
            mstore(0x00, 0x20)
            mstore(0x20, nonces.length)
            calldatacopy(0x40, nonces.offset, end)
            log2(0x00, add(0x40, end), _NONCES_INVALIDATED_EVENT_SIGNATURE, caller())
        }
    }

    /**
     * @dev Invalidates the `nonces` of `signer`.
     *      Emits a `NoncesInvalidated(signer, nonces)` event.
     * @param nonces    An array of nonces to invalidate.
     * @param signer    The signer of the signature.
     * @param signature The signature by the signer.
     */
    function invalidateNoncesForSigner(
        uint256[] calldata nonces,
        address signer,
        bytes calldata signature
    ) external {
        assembly {
            let end := shl(5, nonces.length)
            // Layout the fields of the struct hash.
            mstore(returndatasize(), _INVALIDATE_NONCES_FOR_SIGNER_TYPEHASH)
            mstore(0x20, signer)
            // Compute and store `keccak256(abi.encodePacked(nonces))`.
            calldatacopy(0x40, nonces.offset, end)
            mstore(0x40, keccak256(0x40, end))
            mstore(0x60, sload(add(signer, address()))) // Store the nonce salt.
            mstore(0x40, keccak256(returndatasize(), 0x80)) // Compute and store the struct hash.
            // Layout the fields of the domain separator.
            mstore(0x60, _DOMAIN_TYPEHASH)
            mstore(0x80, _NAME_HASH)
            mstore(0xa0, _VERSION_HASH)
            mstore(0xc0, chainid())
            mstore(0xe0, address())
            mstore(0x20, keccak256(0x60, 0xa0)) // Compute and store the domain separator.
            // Layout the fields of `ecrecover`.
            mstore(returndatasize(), 0x1901) // Store "\x19\x01".
            let digest := keccak256(0x1e, 0x42) // Compute the digest.
            for {} 1 {} {
                if eq(signature.length, 64) {
                    mstore(returndatasize(), digest) // Store the digest.
                    let vs := calldataload(add(signature.offset, 0x20))
                    mstore(0x20, add(shr(255, vs), 27)) // `v`.
                    mstore(0x40, calldataload(signature.offset)) // `r`.
                    mstore(0x60, shr(1, shl(1, vs))) // `s`.
                    let t := staticcall(gas(), 1, 0x00, 0x80, 0x01, 0x20)
                    if iszero(or(iszero(returndatasize()), xor(signer, mload(t)))) { break }
                }
                if eq(signature.length, 65) {
                    mstore(returndatasize(), digest) // Store the digest.
                    calldatacopy(0x40, signature.offset, signature.length) // Copy `r`, `s`, `v`.
                    mstore(0x20, byte(returndatasize(), mload(0x80))) // `v`.
                    let t := staticcall(gas(), 1, 0x00, 0x80, 0x01, 0x20)
                    if iszero(or(iszero(returndatasize()), xor(signer, mload(t)))) { break }
                }
                // ERC1271 fallback.
                let f := shl(224, 0x1626ba7e) // `isValidSignature(bytes32,bytes)`.
                mstore(0x00, f)
                mstore(0x04, digest)
                mstore(0x24, 0x40)
                mstore(0x44, signature.length)
                calldatacopy(0x64, signature.offset, signature.length)
                let t := staticcall(gas(), signer, 0x00, add(signature.length, 0x64), 0x24, 0x20)
                if iszero(and(eq(mload(0x24), f), t)) {
                    mstore(0x00, 0x8baa579f) // `InvalidSignature()`.
                    revert(0x1c, 0x04)
                }
                break
            }

            mstore(0x00, signer)
            // Iterate through all the nonces and set their boolean values in the storage.
            for { let i := 0 } iszero(eq(i, end)) { i := add(i, 0x20) } {
                let nonce := calldataload(add(nonces.offset, i))
                mstore(0x20, nonce)
                let bucketSlot := keccak256(0x00, 0x3f)
                sstore(bucketSlot, or(sload(bucketSlot), shl(and(0xff, nonce), 1)))
            }
            // Emit `NoncesInvalidated(signer, nonces)`.
            mstore(0x00, 0x20)
            mstore(0x20, nonces.length)
            calldatacopy(0x40, nonces.offset, end)
            log2(0x00, add(0x40, end), _NONCES_INVALIDATED_EVENT_SIGNATURE, signer)
        }
    }

    /**
     * @dev Returns whether each of the `nonces` of `signer` has been invalidated.
     * @param signer The signer of the signature.
     * @param nonces An array of nonces.
     * @return A bool array representing whether each nonce has been invalidated.
     */
    function noncesInvalidated(address signer, uint256[] calldata nonces)
        external
        view
        returns (bool[] memory)
    {
        assembly {
            mstore(0x00, signer)
            // Iterate through all the nonces and append their boolean values.
            let end := shl(5, nonces.length)
            for { let i := 0 } iszero(eq(i, end)) { i := add(i, 0x20) } {
                let nonce := calldataload(add(nonces.offset, i))
                mstore(0x20, nonce)
                let bit := and(1, shr(and(0xff, nonce), sload(keccak256(0x00, 0x3f))))
                mstore(add(0x40, i), bit)
            }
            mstore(0x00, 0x20) // Store the memory offset of the `results`.
            mstore(0x20, nonces.length) // Store `data.length` into `results`.
            return(0x00, add(0x40, end))
        }
    }

    /**
     * @dev Increments the nonce salt of `msg.sender`.
     *      For making all unused signatures with the current nonce salt invalid.
     *      Will NOT make invalidated nonces available for use.
     *      Emits a `NonceSaltIncremented(msg.sender, newNonceSalt)` event.
     * @return The new nonce salt.
     */
    function incrementNonceSalt() external returns (uint256) {
        assembly {
            let nonceSaltSlot := add(caller(), address())
            // Increment by some pseudorandom amount from [1..4294967296].
            let nonceSalt := sload(nonceSaltSlot)
            let newNonceSalt := add(add(1, shr(224, blockhash(sub(number(), 1)))), nonceSalt)
            sstore(nonceSaltSlot, newNonceSalt)
            // Emit `NonceSaltIncremented(msg.sender, newNonceSalt)`.
            mstore(0x00, newNonceSalt)
            log2(0x00, 0x20, _NONCE_SALT_INCREMENTED_EVENT_SIGNATURE, caller())
            return(0x00, 0x20)
        }
    }

    /**
     * @dev Increments the nonce salt of `signer`.
     *      For making all unused signatures with the current nonce salt invalid.
     *      Will NOT make invalidated nonces available for use.
     *      Emits a `NonceSaltIncremented(signer, newNonceSalt)` event.
     * @param signer    The signer of the signature.
     * @param signature The signature by the signer.
     * @return The new nonce salt.
     */
    function incrementNonceSaltForSigner(address signer, bytes calldata signature)
        external
        returns (uint256)
    {
        assembly {
            let nonceSaltSlot := add(signer, address())
            let nonceSalt := sload(nonceSaltSlot)
            // Layout the fields of the struct hash.
            mstore(returndatasize(), _INCREMENT_NONCE_SALT_FOR_SIGNER_TYPEHASH)
            mstore(0x20, signer)
            mstore(0x40, nonceSalt) // Store the nonce salt.
            mstore(0x40, keccak256(returndatasize(), 0x60)) // Compute and store the struct hash.
            // Layout the fields of the domain separator.
            mstore(0x60, _DOMAIN_TYPEHASH)
            mstore(0x80, _NAME_HASH)
            mstore(0xa0, _VERSION_HASH)
            mstore(0xc0, chainid())
            mstore(0xe0, address())
            mstore(0x20, keccak256(0x60, 0xa0)) // Compute and store the domain separator.
            // Layout the fields of `ecrecover`.
            mstore(returndatasize(), 0x1901) // Store "\x19\x01".
            let digest := keccak256(0x1e, 0x42) // Compute the digest.
            for {} 1 {} {
                if eq(signature.length, 64) {
                    mstore(returndatasize(), digest) // Store the digest.
                    let vs := calldataload(add(signature.offset, 0x20))
                    mstore(0x20, add(shr(255, vs), 27)) // `v`.
                    mstore(0x40, calldataload(signature.offset)) // `r`.
                    mstore(0x60, shr(1, shl(1, vs))) // `s`.
                    let t := staticcall(gas(), 1, 0x00, 0x80, 0x01, 0x20)
                    if iszero(or(iszero(returndatasize()), xor(signer, mload(t)))) { break }
                }
                if eq(signature.length, 65) {
                    mstore(returndatasize(), digest) // Store the digest.
                    calldatacopy(0x40, signature.offset, signature.length) // Copy `r`, `s`, `v`.
                    mstore(0x20, byte(returndatasize(), mload(0x80))) // `v`.
                    let t := staticcall(gas(), 1, 0x00, 0x80, 0x01, 0x20)
                    if iszero(or(iszero(returndatasize()), xor(signer, mload(t)))) { break }
                }
                // ERC1271 fallback.
                let f := shl(224, 0x1626ba7e) // `isValidSignature(bytes32,bytes)`.
                mstore(0x00, f)
                mstore(0x04, digest)
                mstore(0x24, 0x40)
                mstore(0x44, signature.length)
                calldatacopy(0x64, signature.offset, signature.length)
                let t := staticcall(gas(), signer, 0x00, add(signature.length, 0x64), 0x24, 0x20)
                if iszero(and(eq(mload(0x24), f), t)) {
                    mstore(0x00, 0x8baa579f) // `InvalidSignature()`.
                    revert(0x1c, 0x04)
                }
                break
            }

            // Increment by some pseudorandom amount from [1..4294967296].
            let newNonceSalt := add(add(1, shr(224, blockhash(sub(number(), 1)))), nonceSalt)
            sstore(nonceSaltSlot, newNonceSalt)
            // Emit `NonceSaltIncremented(signer, newNonceSalt)`.
            mstore(0x00, newNonceSalt)
            log2(0x00, 0x20, _NONCE_SALT_INCREMENTED_EVENT_SIGNATURE, signer)
            return(0x00, 0x20)
        }
    }

    /**
     * @dev Returns the nonce salt of `signer`.
     * @param signer The signer of the signature.
     * @return The current nonce salt of `signer`.
     */
    function nonceSaltOf(address signer) external view returns (uint256) {
        assembly {
            mstore(returndatasize(), sload(add(signer, address())))
            return(returndatasize(), 0x20)
        }
    }

    /**
     * @dev Returns the EIP-712 domain information, as specified in
     *      [EIP-5267](https://eips.ethereum.org/EIPS/eip-5267).
     * @return fields            `hex"0f"` (`0b01111`).
     * @return name              `"MulticallerWithSigner"`.
     * @return version           `"1"`.
     * @return chainId           The chain ID which this contract is on.
     * @return verifyingContract `address(this)`, the address of this contract.
     * @return salt              `bytes32(0)` (not used).
     * @return extensions        `[]` (not used).
     */
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
    {
        assembly {
            pop(fields)
            mstore8(returndatasize(), 0x0f)
            pop(name)
            mstore(0x20, 0xe0)
            mstore(0xf5, 0x154d756c746963616c6c6572576974685369676e6572)
            pop(version)
            mstore(0x40, 0x120)
            mstore(0x121, 0x0131)
            pop(chainId)
            mstore(0x60, chainid())
            pop(verifyingContract)
            mstore(0x80, address())
            pop(salt)
            pop(extensions)
            mstore(0xc0, 0x160)
            return(returndatasize(), 0x180)
        }
    }
}
