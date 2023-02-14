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
    address internal constant MULTICALLER = 0x000000000000a9797e1Bb9daD17E838ba5860A82;

    /**
     * @dev Returns the address that called `aggregateWithSender` on the multicaller.
     * @return result The caller address.
     */
    function sender() internal view returns (address result) {
        assembly {
            // Store the function selector of `sender()`.
            mstore(0x00, 0x67e404ce)
            result :=
                mul(
                    mload(0x00),
                    and(
                        eq(returndatasize(), 0x20),
                        staticcall(
                            gas(), // Remaining gas.
                            MULTICALLER, // The multicaller.
                            0x1c, // Start of calldata.
                            0x04, // Length of calldata.
                            0x00, // Start of returndata in memory.
                            0x20 // Length of returndata.
                        )
                    )
                )
        }
    }
}
