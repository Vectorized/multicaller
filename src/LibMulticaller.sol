// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/**
 * @title LibMulticaller
 * @author vectorized.eth
 * @notice Library to read the `msg.sender` of the multicaller with sender contract.
 *
 * @dev Note:
 * The functions in this library do NOT guard against reentrancy.
 * A single transaction can recurse through different Multicallers
 * (e.g. `MulticallerWithSender -> contract -> MulticallerWithSigner -> contract`).
 *
 * Think of these functions like `msg.sender`.
 *
 * If your contract `C` can handle reentrancy safely with plain old `msg.sender`
 * for any `A -> C -> B -> C`, you should be fine substituting `msg.sender` with these functions.
 */
library LibMulticaller {
    /**
     * @dev The address of the multicaller contract.
     */
    address internal constant MULTICALLER = 0x0000000000002Bdbf1Bf3279983603Ec279CC6dF;

    /**
     * @dev The address of the multicaller with sender contract.
     */
    address internal constant MULTICALLER_WITH_SENDER = 0x00000000002Fd5Aeb385D324B580FCa7c83823A0;

    /**
     * @dev The address of the multicaller with signer contract.
     */
    address internal constant MULTICALLER_WITH_SIGNER = 0x000000000000D9ECebf3C23529de49815Dac1c4c;

    /**
     * @dev Returns the caller of `aggregateWithSender` on `MULTICALLER_WITH_SENDER`.
     */
    function multicallerSender() internal view returns (address result) {
        return at(MULTICALLER_WITH_SENDER);
    }

    /**
     * @dev Returns the signer of `aggregateWithSigner` on `MULTICALLER_WITH_SIGNER`.
     */
    function multicallerSigner() internal view returns (address result) {
        return at(MULTICALLER_WITH_SIGNER);
    }

    /**
     * @dev Returns the caller of `aggregateWithSender` on `MULTICALLER_WITH_SENDER`,
     *      if the current context's `msg.sender` is `MULTICALLER_WITH_SENDER`.
     *      Otherwise, returns `msg.sender`.
     */
    function sender() internal view returns (address result) {
        return resolve(MULTICALLER_WITH_SENDER);
    }

    /**
     * @dev Returns the caller of `aggregateWithSigner` on `MULTICALLER_WITH_SIGNER`,
     *      if the current context's `msg.sender` is `MULTICALLER_WITH_SIGNER`.
     *      Otherwise, returns `msg.sender`.
     */
    function signer() internal view returns (address) {
        return resolve(MULTICALLER_WITH_SIGNER);
    }

    /**
     * @dev Returns the caller or signer at `a`.
     * @param a The multicaller with sender / signer.
     */
    function at(address a) internal view returns (address result) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, 0x00)
            if iszero(staticcall(gas(), a, codesize(), 0x00, 0x00, 0x20)) {
                revert(codesize(), codesize()) // For better gas estimation.
            }
            result := mload(0x00)
        }
    }

    /**
     * @dev Returns the caller or signer at `a`, if the caller is `a`.
     * @param a The multicaller with sender / signer.
     */
    function resolve(address a) internal view returns (address result) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, caller())
            if eq(caller(), a) {
                if iszero(staticcall(gas(), a, codesize(), 0x00, 0x00, 0x20)) {
                    revert(codesize(), codesize()) // For better gas estimation.
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
                if iszero(staticcall(gas(), withSender, codesize(), 0x00, 0x00, 0x20)) {
                    revert(codesize(), codesize()) // For better gas estimation.
                }
            }
            let withSigner := MULTICALLER_WITH_SIGNER
            if eq(caller(), withSigner) {
                if iszero(staticcall(gas(), withSigner, codesize(), 0x00, 0x00, 0x20)) {
                    revert(codesize(), codesize()) // For better gas estimation.
                }
            }
            result := mload(0x00)
        }
    }
}
