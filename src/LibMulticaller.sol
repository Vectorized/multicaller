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
    address internal constant MULTICALLER = 0x0000000000009448722dAF1A55EF6D1E71FB162d;

    /**
     * @dev The address of the multicaller with sender contract.
     */
    address internal constant MULTICALLER_WITH_SENDER = 0x00000000002Fd5Aeb385D324B580FCa7c83823A0;

    /**
     * @dev The address of the multicaller with signer contract.
     */
    address internal constant MULTICALLER_WITH_SIGNER = 0x000000000000a89360A6a4786b9B33266F208AF4;

    /**
     * @dev Returns the caller of `aggregateWithSender` on `MULTICALLER_WITH_SENDER`.
     */
    function multicallerSender() internal view returns (address result) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, 0x00)
            if iszero(staticcall(gas(), MULTICALLER_WITH_SENDER, 0x00, 0x00, 0x00, 0x20)) {
                revert(0x00, 0x00) // For better gas estimation.
            }
            result := mload(0x00)
        }
    }

    /**
     * @dev Returns the signer of `aggregateWithSigner` on `MULTICALLER_WITH_SIGNER`.
     */
    function multicallerSigner() internal view returns (address result) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, 0x00)
            if iszero(staticcall(gas(), MULTICALLER_WITH_SIGNER, 0x00, 0x00, 0x00, 0x20)) {
                revert(0x00, 0x00) // For better gas estimation.
            }
            result := mload(0x00)
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
            mstore(0x00, caller())
            let withSender := MULTICALLER_WITH_SENDER
            if eq(caller(), withSender) {
                if iszero(staticcall(gas(), withSender, 0x00, 0x00, 0x00, 0x20)) {
                    revert(0x00, 0x00) // For better gas estimation.
                }
            }
            result := mload(0x00)
        }
    }

    /**
     * @dev Returns the caller of `aggregateWithSender` on `MULTICALLER_WITH_SENDER`,
     *      if the current context's `msg.sender` is `MULTICALLER_WITH_SENDER`.
     *      Returns the signer of `aggregateWithSigner` on `MULTICALLER_WITH_SIGNER`,
     *      if the current context's `msg.sender` is `MULTICALLER_WITH_SIGNER`.
     *      Otherwise, returns `msg.sender`.
     */
    function senderOrSigner() internal view returns (address result) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, caller())
            let withSender := MULTICALLER_WITH_SENDER
            if eq(caller(), withSender) {
                if iszero(staticcall(gas(), withSender, 0x00, 0x00, 0x00, 0x20)) {
                    revert(0x00, 0x00) // For better gas estimation.
                }
            }
            let withSigner := MULTICALLER_WITH_SIGNER
            if eq(caller(), withSigner) {
                if iszero(staticcall(gas(), withSigner, 0x00, 0x00, 0x00, 0x20)) {
                    revert(0x00, 0x00) // For better gas estimation.
                }
            }
            result := mload(0x00)
        }
    }
}
