Original at: https://gist.github.com/0xth0mas/59ea1f31f16e058da27b0607c4dc24b8

# General

No major vulnerabilities were identified.

# Scope

Review for [Vectorized/multicaller commit 8c07107](https://github.com/Vectorized/multicaller/commit/8c071078b29d0037a7f01ec6f346776ec7c89948)

```
src
├── LibMulticaller.sol
└── MulticallerWithSigner.sol
```

---

### Documentation for reentrancy guard bit references incorrect bit location

**Severity:** Informational
**Likelihood:** N/A
**File:** [MulticallerWithSigner](https://github.com/Vectorized/multicaller/blob/8c071078b29d0037a7f01ec6f346776ec7c89948/src/MulticallerWithSigner.sol#L122)

The comment in the constructor detailing the data packing of storage slot 0 references `bit 1` as the location for the `MulticallerWithSigner` reentrancy guard while it is stored at bit 0.

This has no impact to the functionality of `MulticallerWithSigner`. The only potential negative impact would be from a developer forking `MulticallerWithSigner` without understanding the code and making assumptions about the reentrancy guard based on the comment.

**Mitigation:**

Update comment to reflect the reentrancy guard at bit 0.

---

### Potential gas optimization on `resultsOffset` incrementer

**Severity:** Gas Optimization
**Likelihood:** Unknown
**File:** [MulticallerWithSigner](https://github.com/Vectorized/multicaller/blob/8c071078b29d0037a7f01ec6f346776ec7c89948/src/MulticallerWithSigner.sol#L319)

Incrementing the `resultsOffset` value with the necessary padding for ABI encoding of results values requires eight operations that are unnecessary for the final iteration of the loop.

It may be more efficient to move the `resultsOffset` incrementer after the loop end check. Mock tests show a gas savings of 24 gas units for a single call with each additional call in the multicall transaction reducing savings by 6 gas units until it hits a breakeven point at 5 calls and becomes more expensive at 6 calls. 

If the average number of calls included in a multicall transaction to `MulticallerWithSigner` is under 5 it would be beneficial to change the code as follows:

##### From - 
```solidity
                // Advance the `resultsOffset` by `returndatasize() + 0x20`,
                // rounded up to the next multiple of 0x20.
                resultsOffset := and(add(add(resultsOffset, returndatasize()), 0x3f), not(0x1f))
                // Advance the `results` pointer.
                results := add(results, 0x20)
                if eq(results, end) { break }
```

#### To -
```solidity
                // Advance the `results` pointer.
                results := add(results, 0x20)
                if eq(results, end) { break }
                // Advance the `resultsOffset` by `returndatasize() + 0x20`,
                // rounded up to the next multiple of 0x20.
                resultsOffset := and(add(add(resultsOffset, returndatasize()), 0x3f), not(0x1f))
```