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
    address internal constant MULTICALLER = 0x000000000088228fCF7b8af41Faf3955bD0B3A41;

    /**
     * @dev The address of the multicaller with sender contract.
     */
    address internal constant MULTICALLER_WITH_SENDER = 0x00000000002Fd5Aeb385D324B580FCa7c83823A0;

    /**
     * @dev The address of the multicaller with signer contract.
     */
    address internal constant MULTICALLER_WITH_SIGNER = 0x000000000000B06107881d4b55B76Cee8DeC3728;

    /**
     * @dev Returns the caller of `aggregateWithSender` on `MULTICALLER_WITH_SENDER`.
     */
    function multicallerSender() internal view returns (address result) {
        /// @solidity memory-safe-assembly
        assembly {
            if iszero(staticcall(gas(), MULTICALLER_WITH_SENDER, 0x00, 0x00, 0x00, 0x20)) {
                revert(0, 0) // For better gas estimation.
            }
            result := mul(mload(0x00), eq(returndatasize(), 0x20))
        }
    }

    /**
     * @dev Returns the caller of `aggregateWithSigner` on `MULTICALLER_WITH_SIGNER`.
     */
    function multicallerSigner() internal view returns (address result) {
        /// @solidity memory-safe-assembly
        assembly {
            if iszero(staticcall(gas(), MULTICALLER_WITH_SIGNER, 0x00, 0x00, 0x00, 0x20)) {
                revert(0, 0) // For better gas estimation.
            }
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
            for {} 1 {} {
                if eq(caller(), MULTICALLER_WITH_SENDER) {
                    if iszero(staticcall(gas(), MULTICALLER_WITH_SENDER, 0x00, 0x00, 0x00, 0x20)) {
                        revert(0, 0) // For better gas estimation.
                    }
                    result := mload(0x00)
                    break
                }
                result := caller()
                break
            }
        }
    }

    /**
     * @dev Returns the caller of `aggregateWithSender` on `MULTICALLER_WITH_SENDER`,
     *      if the current context's `msg.sender` is `MULTICALLER_WITH_SENDER`.
     *      Returns the caller of `aggregateWithSender` on `MULTICALLER_WITH_SIGNER`,
     *      if the current context's `msg.sender` is `MULTICALLER_WITH_SIGNER`.
     *      Otherwise, returns `msg.sender`.
     */
    function senderOrSigner() internal view returns (address result) {
        /// @solidity memory-safe-assembly
        assembly {
            for {} 1 {} {
                if eq(caller(), MULTICALLER_WITH_SENDER) {
                    if iszero(staticcall(gas(), MULTICALLER_WITH_SENDER, 0x00, 0x00, 0x00, 0x20)) {
                        revert(0, 0) // For better gas estimation.
                    }
                    result := mload(0x00)
                    break
                }
                if eq(caller(), MULTICALLER_WITH_SIGNER) {
                    if iszero(staticcall(gas(), MULTICALLER_WITH_SIGNER, 0x00, 0x00, 0x00, 0x20)) {
                        revert(0, 0) // For better gas estimation.
                    }
                    result := mload(0x00)
                    break
                }
                result := caller()
                break
            }
        }
    }
}
