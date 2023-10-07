// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/**
 * @title Multicaller
 * @author vectorized.eth
 * @notice Contract that allows for efficient aggregation
 *         of multiple calls in a single transaction.
 */
contract Multicaller {
    // =============================================================
    //                            ERRORS
    // =============================================================

    /**
     * @dev The lengths of the input arrays are not the same.
     */
    error ArrayLengthsMismatch();

    // =============================================================
    //                    AGGREGATION OPERATIONS
    // =============================================================

    /**
     * @dev Aggregates multiple calls in a single transaction.
     * @param targets  An array of addresses to call.
     * @param data     An array of calldata to forward to the targets.
     * @param values   How much ETH to forward to each target.
     * @param refundTo The address to transfer any remaining ETH in the contract after the calls.
     *                 If `address(0)`, remaining ETH will NOT be refunded.
     *                 If `address(1)`, remaining ETH will be refunded to `msg.sender`.
     *                 If anything else, remaining ETH will be refunded to `refundTo`.
     * @return An array of the returndata from each call.
     */
    function aggregate(
        address[] calldata targets,
        bytes[] calldata data,
        uint256[] calldata values,
        address refundTo
    ) external payable returns (bytes[] memory) {
        assembly {
            if iszero(and(eq(targets.length, data.length), eq(data.length, values.length))) {
                // Store the function selector of `ArrayLengthsMismatch()`.
                mstore(returndatasize(), 0x3b800a46)
                // Revert with (offset, size).
                revert(0x1c, 0x04)
            }

            let resultsSize := 0x40

            if data.length {
                let results := 0x40
                // Left shift by 5 is equivalent to multiplying by 0x20.
                data.length := shl(5, data.length)
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
                resultsSize := add(resultsOffset, 0x40)
            }

            if refundTo {
                // Force transfers all the remaining ETH in the contract to `refundTo`,
                // with a gas stipend of 100000, which should be enough for most use cases.
                // If sending via a regular call fails, force sends the ETH by
                // creating a temporary contract which uses `SELFDESTRUCT` to force send the ETH.
                if selfbalance() {
                    // If `refundTo` is `address(1)`, replace it with the `msg.sender`.
                    refundTo := xor(refundTo, mul(eq(refundTo, 1), xor(refundTo, caller())))
                    // Transfer the ETH and check if it succeeded or not.
                    if iszero(
                        call(100000, refundTo, selfbalance(), codesize(), 0x00, codesize(), 0x00)
                    ) {
                        mstore(0x00, refundTo) // Store the address in scratch space.
                        mstore8(0x0b, 0x73) // Opcode `PUSH20`.
                        mstore8(0x20, 0xff) // Opcode `SELFDESTRUCT`.
                        // We can directly use `SELFDESTRUCT` in the contract creation.
                        // Compatible with `SENDALL`: https://eips.ethereum.org/EIPS/eip-4758
                        if iszero(create(selfbalance(), 0x0b, 0x16)) {
                            // Coerce gas estimation to provide enough gas for the `create` above.
                            revert(codesize(), codesize())
                        }
                    }
                }
            }

            mstore(0x00, 0x20) // Store the memory offset of the `results`.
            mstore(0x20, targets.length) // Store `targets.length` into `results`.
            // Direct return.
            return(0x00, resultsSize)
        }
    }

    /**
     * @dev For receiving ETH.
     *      Does nothing and returns nothing.
     *      Called instead of `fallback()` if the calldatasize is zero.
     */
    receive() external payable {}

    /**
     * @dev Decompresses the calldata and performs a delegatecall
     *      with the decompressed calldata to itself.
     *
     *      Accompanying JavaScript library to compress the calldata:
     *      https://github.com/vectorized/solady/blob/main/js/solady.js
     *      (See: `LibZip.cdCompress`)
     */
    fallback() external payable {
        assembly {
            // If the calldata starts with the bitwise negation of
            // `bytes4(keccak256("aggregate(address[],bytes[],uint256[],address)"))`.
            let s := calldataload(returndatasize())
            if eq(shr(224, s), 0x66e0daa0) {
                mstore(returndatasize(), not(s))
                let o := 4
                for { let i := o } lt(i, calldatasize()) {} {
                    let c := byte(returndatasize(), calldataload(i))
                    i := add(i, 1)
                    if iszero(c) {
                        let d := byte(returndatasize(), calldataload(i))
                        i := add(i, 1)
                        // Fill with either 0xff or 0x00.
                        mstore(o, not(returndatasize()))
                        if iszero(gt(d, 0x7f)) { codecopy(o, codesize(), add(d, 1)) }
                        o := add(o, add(and(d, 0x7f), 1))
                        continue
                    }
                    mstore8(o, c)
                    o := add(o, 1)
                }
                let success := delegatecall(gas(), address(), 0x00, o, 0x00, 0x00)
                returndatacopy(0x00, 0x00, returndatasize())
                if iszero(success) { revert(0x00, returndatasize()) }
                return(0x00, returndatasize())
            }
            revert(returndatasize(), returndatasize())
        }
    }
}
