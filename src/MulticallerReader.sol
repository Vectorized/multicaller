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
    address internal constant MULTICALLER = 0x0000000000ECE0248caAa88d9D2D3d944CbCa453;

    /**
     * @dev Returns the address that called `aggregateWithSender` on the multicaller.
     * @return result The caller address.
     */
    function sender() internal view returns (address result) {
        assembly {
            result :=
                mul(
                    mload(0x00),
                    and(
                        eq(returndatasize(), 0x20),
                        staticcall(
                            gas(), // Remaining gas.
                            MULTICALLER, // The multicaller.
                            0x00, // Start of calldata.
                            0x00, // Length of calldata.
                            0x00, // Start of returndata in memory.
                            0x20 // Length of returndata.
                        )
                    )
                )
        }
    }
}
