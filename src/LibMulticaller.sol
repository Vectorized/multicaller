// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/**
 * @title LibMulticaller
 * @author vectorized.eth
 * @notice Library to read the `msg.sender` of the multicaller with sender contract.
 */
library LibMulticaller {
    /**
     * @dev The address of the multicaller contract.
     */
    address internal constant MULTICALLER = 0x0000000000e00b934df5E876c6CbE7fDAfc253A6;

    /**
     * @dev The address of the multicaller with sender contract.
     */
    address internal constant MULTICALLER_WITH_SENDER = 0x00000000003248fcE45dFE3f5E1a15Eff24fD644;

    /**
     * @dev Returns the caller of `aggregateWithSender` on `MULTICALLER_WITH_SENDER`.
     */
    function multicallerSender() internal view returns (address result) {
        /// @solidity memory-safe-assembly
        assembly {
            if iszero(
                staticcall(
                    gas(), // Remaining gas.
                    MULTICALLER_WITH_SENDER, // The multicaller.
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
     * @dev Returns the caller of `aggregateWithSender` on `MULTICALLER_WITH_SENDER`,
     *      if the current context's `msg.sender` is `MULTICALLER_WITH_SENDER`.
     *      Otherwise, returns `msg.sender`.
     */
    function sender() internal view returns (address result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := caller()
            if eq(result, MULTICALLER_WITH_SENDER) {
                if iszero(
                    staticcall(
                        gas(), // Remaining gas.
                        MULTICALLER_WITH_SENDER, // The multicaller with sender.
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
