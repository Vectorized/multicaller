// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/**
 * @title MulticallerReader
 * @author vectorized.eth
 * @notice Library to read the `msg.sender` of the multicaller contract.
 */
library MulticallerReader {
    /**
     * @dev The address of the multicaller contract.
     */
    address internal constant MULTICALLER = 0x00000000001927a10DD8E7Da85ccFA2D56347c3C;

    /**
     * @dev Returns the caller of `aggregateWithSender` on the multicaller.
     */
    function multicallerSender() internal view returns (address result) {
        /// @solidity memory-safe-assembly
        assembly {
            if iszero(
                staticcall(
                    gas(), // Remaining gas.
                    MULTICALLER, // The multicaller.
                    0x00, // Start of calldata in memory.
                    0x00, // Length of calldata.
                    0x00, // Start of returndata in memory.
                    0x20 // Length of returndata.
                )
            ) { revert(0, 0) } // For better gas estimation.

            result := mul(mload(0x00), eq(returndatasize(), 0x20))
        }
    }

    /**
     * @dev Returns the caller of `aggregateWithSender` on the multicaller,
     *      if the current context's `msg.sender` is the multicaller.
     *      Otherwise, returns `msg.sender`.
     */
    function sender() internal view returns (address result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := caller()
            if eq(result, MULTICALLER) {
                if iszero(
                    staticcall(
                        gas(), // Remaining gas.
                        MULTICALLER, // The multicaller.
                        0x00, // Start of calldata in memory.
                        0x00, // Length of calldata.
                        0x00, // Start of returndata in memory.
                        0x20 // Length of returndata.
                    )
                ) { revert(0, 0) } // For better gas estimation.

                result := mul(mload(0x00), eq(returndatasize(), 0x20))
            }
        }
    }
}
