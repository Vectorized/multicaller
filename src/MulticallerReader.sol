// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/**
 * @title MulticallerReader
 * @author vectorized.eth
 * @notice Library to read the `sender` of the multicaller contract.
 */
library MulticallerReader {
    /**
     * @dev The address of the multicaller contract.
     */
    address internal constant MULTICALLER = 0x00000000002222A40AF12b26A2b59a8fe93445a6;

    /**
     * @dev Returns the address that called `aggregateWithSender` on the multicaller.
     */
    function multicallerSender() internal view returns (address result) {
        /// @solidity memory-safe-assembly
        assembly {
            result :=
                mul(
                    mload(0x00),
                    and(
                        eq(returndatasize(), 0x20),
                        staticcall(
                            gas(), // Remaining gas.
                            MULTICALLER, // The multicaller.
                            0x00, // Start of calldata in memory.
                            0x00, // Length of calldata.
                            0x00, // Start of returndata in memory.
                            0x20 // Length of returndata.
                        )
                    )
                )
        }
    }

    /**
     * @dev Returns the address that called `aggregateWithSender` on the multicaller,
     *      if `msg.sender` is the multicaller.
     *      Otherwise, returns `msg.sender`.
     */
    function sender() internal view returns (address result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := caller()
            if eq(result, MULTICALLER) {
                result :=
                    mul(
                        mload(0x00),
                        and(
                            eq(returndatasize(), 0x20),
                            staticcall(
                                gas(), // Remaining gas.
                                MULTICALLER, // The multicaller.
                                0x00, // Start of calldata in memory.
                                0x00, // Length of calldata.
                                0x00, // Start of returndata in memory.
                                0x20 // Length of returndata.
                            )
                        )
                    )
            }
        }
    }
}
