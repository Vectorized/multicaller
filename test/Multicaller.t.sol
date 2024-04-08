// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "./utils/TestPlus.sol";
import {MulticallerEtcher} from "../src/MulticallerEtcher.sol";
import {Multicaller} from "../src/Multicaller.sol";
import {MulticallerWithSender} from "../src/MulticallerWithSender.sol";
import {MulticallerWithSigner} from "../src/MulticallerWithSigner.sol";
import {LibMulticaller} from "../src/LibMulticaller.sol";
import {MockERC1271Wallet} from "./utils/mocks/MockERC1271Wallet.sol";
import {MockERC1271Malicious} from "./utils/mocks/MockERC1271Malicious.sol";

/**
 * @dev Target contract for the multicaller for testing purposes.
 */
contract MulticallerTarget {
    error CustomError();

    string private _name;

    constructor(string memory name_) {
        _name = name_;
    }

    struct Tuple {
        uint256 a;
        uint256 b;
    }

    function revertsWithString(string memory e) external pure {
        revert(e);
    }

    function revertsWithCustomError() external pure {
        revert CustomError();
    }

    function revertsWithNothing() external pure {
        revert();
    }

    function returnsTuple(uint256 a, uint256 b) external pure returns (Tuple memory tuple) {
        tuple = Tuple({a: a, b: b});
    }

    function returnsString(string calldata s) external pure returns (string memory) {
        return s;
    }

    uint256 public paid;

    function pay() external payable {
        paid += msg.value;
    }

    function returnsSender() external view returns (address) {
        return LibMulticaller.sender();
    }

    function returnsMulticallerSender() external view returns (address) {
        return LibMulticaller.multicallerSender();
    }

    function returnsMulticallerSigner() external view returns (address) {
        return LibMulticaller.multicallerSigner();
    }

    function returnsSenderOrSigner() external view returns (address) {
        return LibMulticaller.senderOrSigner();
    }

    function name() external view returns (string memory) {
        return _name;
    }
}

contract FallbackTarget {
    uint256 public hashSum;

    fallback() external payable {
        _fallback();
    }

    receive() external payable {
        _fallback();
    }

    function _fallback() internal {
        assembly {
            calldatacopy(0x00, 0x00, calldatasize())
            let h := keccak256(0x00, calldatasize())
            sstore(hashSum.slot, add(sload(hashSum.slot), h))
            return(0x00, calldatasize())
        }
    }
}

contract MulticallerTest is TestPlus {
    Multicaller multicaller;
    MulticallerWithSender multicallerWithSender;
    MulticallerWithSigner multicallerWithSigner;

    MulticallerTarget targetA;
    MulticallerTarget targetB;

    FallbackTarget fallbackTargetA;
    FallbackTarget fallbackTargetB;

    address erc721Signer;
    uint256 erc721SignerPrivateKey;
    address erc1271Wallet;
    address erc1271Malicious;

    event NoncesInvalidated(address indexed signer, uint256[] nonces);

    event NonceSaltIncremented(address indexed signer, uint256 newNonceSalt);

    function setUp() public virtual {
        multicaller = MulticallerEtcher.multicaller();
        multicallerWithSender = MulticallerEtcher.multicallerWithSender();
        multicallerWithSigner = MulticallerEtcher.multicallerWithSigner();

        // Uncomment as needed to test the source files directly:
        // _etchMulticaller();
        // _etchMulticallerWithSender();
        // _etchMulticallerWithSigner();

        _deployTargets();
    }

    function _etchMulticaller() internal {
        vm.etch(LibMulticaller.MULTICALLER, address(new Multicaller()).code);
        multicaller = Multicaller(payable(LibMulticaller.MULTICALLER));
    }

    function _etchMulticallerWithSender() internal {
        vm.etch(LibMulticaller.MULTICALLER_WITH_SENDER, address(new MulticallerWithSender()).code);
        vm.store(LibMulticaller.MULTICALLER_WITH_SENDER, 0, bytes32(uint256(1 << 160)));
        multicallerWithSender =
            MulticallerWithSender(payable(LibMulticaller.MULTICALLER_WITH_SENDER));
    }

    function _etchMulticallerWithSigner() internal {
        vm.etch(LibMulticaller.MULTICALLER_WITH_SIGNER, address(new MulticallerWithSigner()).code);
        vm.store(LibMulticaller.MULTICALLER_WITH_SIGNER, 0, bytes32(uint256(1)));
        multicallerWithSigner =
            MulticallerWithSigner(payable(LibMulticaller.MULTICALLER_WITH_SIGNER));
    }

    function _deployTargets() internal {
        targetA = new MulticallerTarget("A");
        targetB = new MulticallerTarget("B");
        fallbackTargetA = new FallbackTarget();
        fallbackTargetB = new FallbackTarget();
    }

    function _deployERC1271Contracts() internal {
        (erc721Signer, erc721SignerPrivateKey) = _randomSigner();
        erc1271Wallet = address(new MockERC1271Wallet(erc721Signer));
        erc1271Malicious = address(new MockERC1271Malicious());
    }

    function testMulticallerRefund(uint256) public {
        uint256 payment = _bound(_random(), 0, type(uint128).max);

        vm.deal(address(this), type(uint160).max);

        address[] memory targets = new address[](1);
        targets[0] = address(targetA);
        bytes[] memory data = new bytes[](1);
        data[0] = abi.encodeWithSelector(MulticallerTarget.pay.selector);
        uint256[] memory values = new uint256[](1);
        values[0] = payment;

        multicaller.aggregate{value: address(this).balance}(targets, data, values, address(1));
        assertEq(address(this).balance, type(uint160).max - payment);

        uint256 excess = _bound(_random(), 0, type(uint128).max);
        uint256 value = payment + excess;
        multicaller.aggregate{value: value}(targets, data, values, address(fallbackTargetA));
        assertEq(address(fallbackTargetA).balance, excess);
    }

    function testMulticallerRevertWithMessage(string memory revertMessage) public {
        address[] memory targets = new address[](1);
        targets[0] = address(targetA);
        bytes[] memory data = new bytes[](1);
        data[0] =
            abi.encodeWithSelector(MulticallerTarget.revertsWithString.selector, revertMessage);
        vm.expectRevert(bytes(revertMessage));
        multicaller.aggregate(targets, data, new uint256[](1), address(0));
        vm.expectRevert(bytes(revertMessage));
        multicallerWithSender.aggregateWithSender(targets, data, new uint256[](1));
    }

    function testMulticallerRevertWithMessage() public {
        testMulticallerRevertWithMessage("Milady");
    }

    function testMulticallerRevertWithCustomError() public {
        address[] memory targets = new address[](1);
        targets[0] = address(targetA);
        bytes[] memory data = new bytes[](1);
        data[0] = abi.encodeWithSelector(MulticallerTarget.revertsWithCustomError.selector);
        vm.expectRevert(MulticallerTarget.CustomError.selector);
        multicaller.aggregate(targets, data, new uint256[](1), address(0));
        vm.expectRevert(MulticallerTarget.CustomError.selector);
        multicallerWithSender.aggregateWithSender(targets, data, new uint256[](1));
    }

    function testMulticallerRevertWithNothing() public {
        address[] memory targets = new address[](1);
        targets[0] = address(targetA);
        bytes[] memory data = new bytes[](1);
        data[0] = abi.encodeWithSelector(MulticallerTarget.revertsWithNothing.selector);
        vm.expectRevert();
        multicaller.aggregate(targets, data, new uint256[](1), address(0));
        vm.expectRevert();
        multicallerWithSender.aggregateWithSender(targets, data, new uint256[](1));
    }

    function testMulticallerReturnDataIsProperlyEncoded(
        uint256 a0,
        uint256 b0,
        uint256 a1,
        uint256 b1
    ) public {
        address[] memory targets = new address[](2);
        targets[0] = address(targetA);
        targets[1] = address(targetB);
        bytes[] memory data = new bytes[](2);
        data[0] = abi.encodeWithSelector(MulticallerTarget.returnsTuple.selector, a0, b0);
        data[1] = abi.encodeWithSelector(MulticallerTarget.returnsTuple.selector, a1, b1);
        bytes[] memory results = multicaller.aggregate(targets, data, new uint256[](2), address(0));
        MulticallerTarget.Tuple memory t0 = abi.decode(results[0], (MulticallerTarget.Tuple));
        MulticallerTarget.Tuple memory t1 = abi.decode(results[1], (MulticallerTarget.Tuple));
        assertEq(t0.a, a0);
        assertEq(t0.b, b0);
        assertEq(t1.a, a1);
        assertEq(t1.b, b1);
        assertEq(
            abi.encode(multicallerWithSender.aggregateWithSender(targets, data, new uint256[](2))),
            abi.encode(results)
        );
    }

    function testMulticallerReturnDataIsProperlyEncoded(
        string memory s0,
        string memory s1,
        uint256 n
    ) public {
        n = _bound(_random(), 0, 5);
        uint256[] memory choices = new uint256[](n);
        address[] memory targets = new address[](n);
        bytes[] memory data = new bytes[](n);
        for (uint256 i; i != n; ++i) {
            targets[i] = _random() % 2 == 0 ? address(targetA) : address(targetB);
            uint256 c = _random() % 2;
            choices[i] = c;
            string memory s = c == 0 ? s0 : s1;
            data[i] = abi.encodeWithSelector(MulticallerTarget.returnsString.selector, s);
        }
        bytes[] memory results = multicaller.aggregate(targets, data, new uint256[](n), address(0));
        for (uint256 i; i != n; ++i) {
            string memory s = choices[i] == 0 ? s0 : s1;
            assertEq(abi.decode(results[i], (string)), s);
        }
        assertEq(
            abi.encode(multicallerWithSender.aggregateWithSender(targets, data, new uint256[](n))),
            abi.encode(results)
        );

        (bool success, bytes memory encodedResults) = address(multicaller).call(
            _cdCompress(
                abi.encodeWithSelector(
                    Multicaller.aggregate.selector, targets, data, new uint256[](n), address(0)
                )
            )
        );
        assertTrue(success);
        assertEq(encodedResults, abi.encode(results));
    }

    function testMulticallerCdFallback(string memory s) public {
        address[] memory targets = new address[](2);
        targets[0] = address(targetA);
        targets[1] = address(targetA);
        bytes[] memory data = new bytes[](2);
        data[0] = abi.encodeWithSelector(MulticallerTarget.returnsString.selector, s);
        data[1] = abi.encodeWithSelector(MulticallerTarget.returnsString.selector, s);
        uint256[] memory values = new uint256[](2);

        bytes[] memory results = multicaller.aggregate(targets, data, values, address(0));

        (bool success, bytes memory encodedResults) = address(multicaller).call(
            _cdCompress(
                abi.encodeWithSelector(
                    Multicaller.aggregate.selector, targets, data, values, address(0)
                )
            )
        );
        assertTrue(success);
        assertEq(encodedResults, abi.encode(results));

        uint256 value = _bound(_random(), 0, 1 ether);
        vm.deal(address(this), value);
        (success, encodedResults) = address(multicaller).call{value: value}("");
        assertTrue(success);
        assertEq(encodedResults.length, 0);
        assertEq(address(multicaller).balance, value);
    }

    function testMulticallerReturnDataIsProperlyEncoded() public {
        testMulticallerReturnDataIsProperlyEncoded(0, 1, 2, 3);
    }

    function testMulticallerWithNoData() public {
        address[] memory targets = new address[](0);
        bytes[] memory data = new bytes[](0);
        assertEq(multicaller.aggregate(targets, data, new uint256[](0), address(0)).length, 0);
        assertEq(
            multicallerWithSender.aggregateWithSender(targets, data, new uint256[](0)).length, 0
        );
    }

    function testMulticallerForwardsMessageValue() public {
        address[] memory targets = new address[](4);
        targets[0] = address(targetA);
        targets[1] = address(targetA);
        targets[2] = address(targetB);
        targets[3] = address(targetB);
        bytes[] memory data = new bytes[](4);
        data[0] = abi.encodeWithSelector(MulticallerTarget.pay.selector);
        data[1] = abi.encodeWithSelector(MulticallerTarget.pay.selector);
        data[2] = abi.encodeWithSelector(MulticallerTarget.pay.selector);
        data[3] = abi.encodeWithSelector(MulticallerTarget.pay.selector);
        uint256[] memory values = new uint256[](4);
        values[0] = 1;
        values[1] = 0;
        values[2] = 0;
        values[3] = 3;
        multicaller.aggregate{value: 4}(targets, data, values, address(0));
        multicallerWithSender.aggregateWithSender{value: 4}(targets, data, values);
        assertEq(targetA.paid(), 2);
        assertEq(targetB.paid(), 6);

        targets[0] = address(targetB);
        targets[1] = address(targetB);
        targets[2] = address(targetA);
        targets[3] = address(targetA);
        values[0] = 0;
        values[3] = 5;
        multicaller.aggregate{value: 5}(targets, data, values, address(0));
        multicallerWithSender.aggregateWithSender{value: 5}(targets, data, values);
        assertEq(targetA.paid(), 12);
        assertEq(targetB.paid(), 6);

        targets = new address[](1);
        targets[0] = address(targetA);
        data = new bytes[](1);
        data[0] = abi.encodeWithSelector(MulticallerTarget.pay.selector);
        values = new uint256[](1);
        values[0] = 3;
        multicaller.aggregate{value: 3}(targets, data, values, address(0));
        multicallerWithSender.aggregateWithSender{value: 3}(targets, data, values);
        assertEq(targetA.paid(), 18);
    }

    function testMulticallerGetNames() public {
        address[] memory targets = new address[](2);
        targets[0] = address(targetA);
        targets[1] = address(targetB);
        bytes[] memory data = new bytes[](2);
        data[0] = abi.encodeWithSelector(MulticallerTarget.name.selector);
        data[1] = abi.encodeWithSelector(MulticallerTarget.name.selector);
        bytes[] memory results = multicaller.aggregate(targets, data, new uint256[](2), address(0));
        assertEq(abi.decode(results[0], (string)), "A");
        assertEq(abi.decode(results[1], (string)), "B");
        assertEq(
            abi.encode(multicallerWithSender.aggregateWithSender(targets, data, new uint256[](2))),
            abi.encode(results)
        );
    }

    function testMulticallerReentrancyGuard() public {
        address[] memory targets = new address[](1);
        targets[0] = address(multicallerWithSender);
        bytes[] memory data = new bytes[](1);
        data[0] = abi.encodeWithSelector(
            MulticallerWithSender.aggregateWithSender.selector,
            new address[](0),
            new bytes[](0),
            new uint256[](0)
        );
        vm.expectRevert(MulticallerWithSender.Reentrancy.selector);
        multicallerWithSender.aggregateWithSender(targets, data, new uint256[](1));
    }

    function testMulticallerTargetGetMulticallerSender() public {
        address[] memory targets = new address[](1);
        targets[0] = address(targetA);
        bytes[] memory data = new bytes[](1);
        data[0] = abi.encodeWithSelector(MulticallerTarget.returnsMulticallerSender.selector);

        bytes[] memory results =
            multicallerWithSender.aggregateWithSender(targets, data, new uint256[](1));
        assertEq(abi.decode(results[0], (address)), address(this));
        data[0] = abi.encodeWithSelector(MulticallerTarget.returnsSender.selector);
        results = multicallerWithSender.aggregateWithSender(targets, data, new uint256[](1));
        assertEq(abi.decode(results[0], (address)), address(this));

        data[0] = abi.encodeWithSelector(MulticallerTarget.returnsSenderOrSigner.selector);
        results = multicallerWithSender.aggregateWithSender(targets, data, new uint256[](1));
        assertEq(abi.decode(results[0], (address)), address(this));
    }

    function testMulticallerSenderDoesNotRevertWithoutMulticallerDeployed() public {
        vm.etch(LibMulticaller.MULTICALLER_WITH_SENDER, "");
        assertEq(LibMulticaller.multicallerSender(), address(0));
    }

    struct _TestTemps {
        address[] targets;
        bytes[] data;
        uint256[] values;
        uint256 nonce;
        uint256 nonceSalt;
        bytes signature;
        address signer;
        uint256 privateKey;
    }

    function _randomBytes() internal returns (bytes memory result) {
        uint256 r0 = _random();
        uint256 r1 = _random();
        uint256 r2 = _random();
        uint256 r3 = _random();
        uint256 n = _random() % 128;
        assembly {
            result := mload(0x40)
            mstore(result, n)
            mstore(add(result, 0x20), r0)
            mstore(add(result, 0x40), r1)
            mstore(add(result, 0x60), r2)
            mstore(add(result, 0x80), r3)
            mstore(0x40, add(result, 0xa0))
        }
    }

    function _generateSignature(_TestTemps memory t) internal view {
        unchecked {
            bytes32[] memory dataHashes = new bytes32[](t.data.length);
            for (uint256 i; i < t.data.length; ++i) {
                dataHashes[i] = keccak256(t.data[i]);
            }
            bytes32 digest = keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    _multicallerWithSignerDomainSeparator(),
                    keccak256(
                        abi.encode(
                            keccak256(
                                "AggregateWithSigner(address signer,address[] targets,bytes[] data,uint256[] values,uint256 nonce,uint256 nonceSalt)"
                            ),
                            t.signer,
                            keccak256(abi.encodePacked(t.targets)),
                            keccak256(abi.encodePacked(dataHashes)),
                            keccak256(abi.encodePacked(t.values)),
                            t.nonce,
                            t.nonceSalt
                        )
                    )
                )
            );
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(t.privateKey, digest);
            t.signature = abi.encodePacked(r, s, v);
        }
    }

    function _nextNonceSalt(uint256 nonceSalt) internal view returns (uint256 result) {
        assembly {
            result := add(add(1, shr(224, blockhash(sub(number(), 1)))), nonceSalt)
        }
    }

    function _testTemps() internal returns (_TestTemps memory t) {
        (t.signer, t.privateKey) = _randomSigner();
        uint256 n = _random() % 3; // 0, 1, 2
        t.targets = new address[](n);
        t.data = new bytes[](n);
        t.values = new uint256[](n);
        for (uint256 i; i < n; ++i) {
            t.targets[i] = _random() % 2 == 0 ? address(fallbackTargetA) : address(fallbackTargetB);
            t.data[i] = _randomBytes();
            t.values[i] = _random() % 32;
        }
        t.nonce = _random();

        {
            uint256 newNonceSalt = _nextNonceSalt(multicallerWithSigner.nonceSaltOf(t.signer));
            vm.expectEmit(true, true, true, true);
            emit NonceSaltIncremented(t.signer, newNonceSalt);
            vm.prank(t.signer);
            assertEq(multicallerWithSigner.incrementNonceSalt(), newNonceSalt);
            t.nonceSalt = multicallerWithSigner.nonceSaltOf(t.signer);
        }
        _generateSignature(t);
    }

    function testMulticallerWithSigner(uint256) public {
        _TestTemps memory t = _testTemps();

        vm.deal(address(this), type(uint160).max);

        if (_random() % 2 == 0) {
            uint256 r = _random() % 3;
            if (r == 0) {
                uint256 newNonceSalt = _nextNonceSalt(multicallerWithSigner.nonceSaltOf(t.signer));
                vm.expectEmit(true, true, true, true);
                emit NonceSaltIncremented(t.signer, newNonceSalt);
                vm.prank(t.signer);
                multicallerWithSigner.incrementNonceSalt();
                _callAndCheckMulticallerWithSigner(
                    t, MulticallerWithSigner.InvalidSignature.selector
                );
                return;
            }
            if (r == 1) {
                uint256[] memory noncesToInvalidate = new uint256[](1);
                noncesToInvalidate[0] = t.nonce;
                vm.prank(t.signer);
                multicallerWithSigner.invalidateNonces(noncesToInvalidate);
                _callAndCheckMulticallerWithSigner(
                    t, MulticallerWithSigner.InvalidSignature.selector
                );
                return;
            }
            if (r == 2) {
                t.signature[0] = bytes1(uint8(t.signature[0]) ^ 1);
                _callAndCheckMulticallerWithSigner(
                    t, MulticallerWithSigner.InvalidSignature.selector
                );
                return;
            }
        }

        bytes[] memory results = _callAndCheckMulticallerWithSigner(t, bytes4(0));

        unchecked {
            uint256 expectedHashSum;
            for (uint256 i; i < t.data.length; ++i) {
                expectedHashSum += uint256(keccak256(t.data[i]));
            }
            uint256 actualHashSum = fallbackTargetA.hashSum() + fallbackTargetB.hashSum();
            assertEq(actualHashSum, expectedHashSum);
            for (uint256 i; i < results.length; ++i) {
                assertEq(keccak256(results[i]), keccak256(t.data[i]));
            }
        }

        _checkBalance(t, address(fallbackTargetA));
        _checkBalance(t, address(fallbackTargetB));

        if (_random() % 2 == 0) {
            _callAndCheckMulticallerWithSigner(t, MulticallerWithSigner.InvalidSignature.selector);
        }
    }

    function testMulticallerWithSignerWithERC1271(uint256) public {
        _deployERC1271Contracts();
        _TestTemps memory t = _testTemps();
        t.signer = erc1271Wallet;
        t.privateKey = erc721SignerPrivateKey;
        t.nonceSalt = multicallerWithSigner.nonceSaltOf(t.signer);
        _generateSignature(t);

        vm.deal(address(this), type(uint160).max);

        if (_random() % 2 == 0) {
            t.signer = erc1271Malicious;
            _callAndCheckMulticallerWithSigner(t, MulticallerWithSigner.InvalidSignature.selector);
        } else {
            bytes[] memory results = _callAndCheckMulticallerWithSigner(t, bytes4(0));

            unchecked {
                uint256 expectedHashSum;
                for (uint256 i; i < t.data.length; ++i) {
                    expectedHashSum += uint256(keccak256(t.data[i]));
                }
                uint256 actualHashSum = fallbackTargetA.hashSum() + fallbackTargetB.hashSum();
                assertEq(actualHashSum, expectedHashSum);
                for (uint256 i; i < results.length; ++i) {
                    assertEq(keccak256(results[i]), keccak256(t.data[i]));
                }
            }
        }
    }

    function _checkBalance(_TestTemps memory t, address target) internal {
        unchecked {
            uint256 expected;
            for (uint256 i; i < t.data.length; ++i) {
                if (t.targets[i] == target) {
                    expected += t.values[i];
                }
            }
            assertEq(target.balance, expected);
        }
    }

    function testMulticallerWithSignerReentrancyGuard() public {
        _TestTemps memory t = _testTemps();
        t.targets = new address[](1);
        t.targets[0] = address(multicallerWithSigner);

        t.data = new bytes[](1);
        t.data[0] = abi.encodeWithSelector(
            MulticallerWithSigner.aggregateWithSigner.selector,
            "",
            new address[](0),
            new bytes[](0),
            new uint256[](0),
            0,
            0,
            address(0),
            ""
        );

        t.values = new uint256[](1);

        _generateSignature(t);

        _callAndCheckMulticallerWithSigner(t, MulticallerWithSigner.Reentrancy.selector);
    }

    function testMulticallerWithSignerRevert() public {
        string memory revertMessage = "Hehehehe";

        _TestTemps memory t = _testTemps();
        t.targets = new address[](1);
        t.targets[0] = address(targetA);

        t.values = new uint256[](1);

        t.data = new bytes[](1);
        t.data[0] =
            abi.encodeWithSelector(MulticallerTarget.revertsWithString.selector, revertMessage);

        _generateSignature(t);

        vm.expectRevert(bytes(revertMessage));
        _callMulticallerWithSigner(t, 0);

        t.data[0] = abi.encodeWithSelector(MulticallerTarget.revertsWithCustomError.selector);

        _generateSignature(t);

        vm.expectRevert(MulticallerTarget.CustomError.selector);
        _callMulticallerWithSigner(t, 0);

        t.data[0] = abi.encodeWithSelector(MulticallerTarget.revertsWithNothing.selector);

        _generateSignature(t);

        vm.expectRevert();
        _callMulticallerWithSigner(t, 0);
    }

    function testMulticallerWithSignerGetMulticallerSigner() public {
        _TestTemps memory t = _testTemps();
        t.targets = new address[](4);
        t.targets[0] = address(targetA);
        t.targets[1] = address(targetA);
        t.targets[2] = address(targetA);
        t.targets[3] = address(targetA);

        t.data = new bytes[](4);
        t.data[0] = abi.encodeWithSelector(MulticallerTarget.returnsMulticallerSigner.selector);
        t.data[1] = abi.encodeWithSelector(MulticallerTarget.returnsSenderOrSigner.selector);
        t.data[2] = abi.encodeWithSelector(MulticallerTarget.returnsSender.selector);
        t.data[3] = abi.encodeWithSelector(MulticallerTarget.returnsMulticallerSender.selector);

        t.values = new uint256[](4);

        _generateSignature(t);

        bytes[] memory results = _callAndCheckMulticallerWithSigner(t, bytes4(0));
        assertEq(abi.decode(results[0], (address)), t.signer);
        assertEq(abi.decode(results[1], (address)), t.signer);
        assertEq(abi.decode(results[2], (address)), address(multicallerWithSigner));
        assertEq(abi.decode(results[3], (address)), address(0));
    }

    function testMulticallerWithSignerWithNoData() public {
        _TestTemps memory t = _testTemps();
        t.targets = new address[](0);

        t.data = new bytes[](0);

        t.values = new uint256[](0);

        _generateSignature(t);

        bytes[] memory results = _callAndCheckMulticallerWithSigner(t, bytes4(0));
        assertEq(results.length, 0);

        _callAndCheckMulticallerWithSigner(t, MulticallerWithSigner.InvalidSignature.selector);
    }

    function testMulticallerWithSignerEIP712Domain() public {
        vm.chainId(12345);

        (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        ) = multicallerWithSigner.eip712Domain();

        assertEq(fields, bytes1(hex"0f"));
        assertEq(name, "MulticallerWithSigner");
        assertEq(version, "1");
        assertEq(chainId, block.chainid);
        assertEq(verifyingContract, address(multicallerWithSigner));
        assertEq(salt, bytes32(0));
        assertEq(extensions.length, 0);
    }

    function testMulticallerWithSignerNonPayableFunctions() public {
        bool success;
        bytes memory data;
        vm.deal(address(this), 1 ether);

        data = abi.encodeWithSelector(MulticallerWithSigner.nonceSaltOf.selector, address(this));
        (success,) = address(multicallerWithSigner).call{value: 1}(data);
        assertFalse(success);
        data = abi.encodeWithSelector(MulticallerWithSigner.nonceSaltOf.selector, address(this));
        (success,) = address(multicallerWithSigner).call{value: 0}(data);
        assertTrue(success);

        data = abi.encodeWithSelector(MulticallerWithSigner.incrementNonceSalt.selector);
        (success,) = address(multicallerWithSigner).call{value: 1}(data);
        assertFalse(success);
        data = abi.encodeWithSelector(MulticallerWithSigner.incrementNonceSalt.selector);
        (success,) = address(multicallerWithSigner).call{value: 0}(data);
        assertTrue(success);
    }

    function _callMulticallerWithSigner(_TestTemps memory t, uint256 value)
        internal
        returns (bytes[] memory results)
    {
        results = multicallerWithSigner.aggregateWithSigner{value: value}(
            t.targets, t.data, t.values, t.nonce, t.signer, _maybeMake2098(t.signature)
        );
    }

    function _callAndCheckMulticallerWithSigner(_TestTemps memory t, bytes4 errorSelector)
        internal
        returns (bytes[] memory results)
    {
        uint256 valuesSum;
        unchecked {
            for (uint256 i; i < t.values.length; ++i) {
                valuesSum += t.values[i];
            }
        }

        uint256[] memory nonces = new uint256[](1);
        nonces[0] = t.nonce;

        if (errorSelector == bytes4(0)) {
            vm.expectEmit(true, true, true, true);
            emit NoncesInvalidated(t.signer, nonces);
        } else {
            vm.expectRevert(errorSelector);
        }

        results = _callMulticallerWithSigner(t, valuesSum);

        if (errorSelector == bytes4(0)) {
            bool[] memory invalidated = multicallerWithSigner.noncesInvalidated(t.signer, nonces);
            assertEq(invalidated[0], true);
        }
    }

    function testMulticallerWithSignerInvalidateNonces(uint256) public {
        unchecked {
            uint256[] memory nonces = new uint256[](_random() % 4);
            if (_random() % 2 == 0) {
                for (uint256 i; i < nonces.length; ++i) {
                    nonces[i] = _random();
                }
            } else {
                for (uint256 i; i < nonces.length; ++i) {
                    nonces[i] = _random() % 8;
                }
            }

            (address signer, uint256 privateKey) = _randomSigner();

            bool[] memory invalidated = multicallerWithSigner.noncesInvalidated(signer, nonces);
            for (uint256 i; i < nonces.length; ++i) {
                assertEq(invalidated[i], false);
            }

            if (_random() % 2 == 0) {
                vm.prank(signer);
                vm.expectEmit(true, true, true, true);
                emit NoncesInvalidated(signer, nonces);
                multicallerWithSigner.invalidateNonces(nonces);
            } else {
                bytes memory signature =
                    _generateInvalidateNoncesSignature(nonces, signer, privateKey);
                vm.expectEmit(true, true, true, true);
                emit NoncesInvalidated(signer, nonces);
                multicallerWithSigner.invalidateNoncesForSigner(
                    nonces, signer, _maybeMake2098(signature)
                );
            }

            invalidated = multicallerWithSigner.noncesInvalidated(signer, nonces);
            for (uint256 i; i < nonces.length; ++i) {
                assertEq(invalidated[i], true);
            }

            {
                (address anotherSigner,) = _randomSigner();
                invalidated = multicallerWithSigner.noncesInvalidated(anotherSigner, nonces);
                for (uint256 i; i < nonces.length; ++i) {
                    assertEq(invalidated[i], anotherSigner == signer);
                }
            }

            uint256[] memory otherNonces = new uint256[](1);
            otherNonces[0] = _random();
            bool expectedUsed;
            for (uint256 i; i < nonces.length; ++i) {
                if (nonces[i] == otherNonces[0]) expectedUsed = true;
            }
            invalidated = multicallerWithSigner.noncesInvalidated(signer, otherNonces);
            assertEq(invalidated[0], expectedUsed);
        }
    }

    function testMulticallerWithSignerInvalidateNoncesWithERC1271(uint256) public {
        _deployERC1271Contracts();
        unchecked {
            uint256[] memory nonces = new uint256[](_random() % 4);
            if (_random() % 2 == 0) {
                for (uint256 i; i < nonces.length; ++i) {
                    nonces[i] = _random();
                }
            } else {
                for (uint256 i; i < nonces.length; ++i) {
                    nonces[i] = _random() % 8;
                }
            }

            bytes memory signature =
                _generateInvalidateNoncesSignature(nonces, erc1271Wallet, erc721SignerPrivateKey);

            vm.expectRevert(MulticallerWithSigner.InvalidSignature.selector);
            multicallerWithSigner.invalidateNoncesForSigner(
                nonces, erc1271Malicious, _maybeMake2098(signature)
            );

            vm.expectEmit(true, true, true, true);
            emit NoncesInvalidated(erc1271Wallet, nonces);
            multicallerWithSigner.invalidateNoncesForSigner(
                nonces, erc1271Wallet, _maybeMake2098(signature)
            );

            vm.expectRevert(MulticallerWithSigner.InvalidSignature.selector);
            multicallerWithSigner.invalidateNoncesForSigner(
                nonces, erc1271Malicious, _maybeMake2098(signature)
            );
        }
    }

    function testMultiCallerWithSignerIncrementNonceSalt(uint256) public {
        (address signer, uint256 privateKey) = _randomSigner();

        for (uint256 q; q < 2; ++q) {
            uint256 nonceSaltBefore = multicallerWithSigner.nonceSaltOf(signer);
            uint256 nextNonceSalt = _nextNonceSalt(nonceSaltBefore);
            if (_random() % 2 == 0) {
                vm.prank(signer);
                vm.expectEmit(true, true, true, true);
                emit NonceSaltIncremented(signer, nextNonceSalt);
                multicallerWithSigner.incrementNonceSalt();
            } else {
                bytes memory signature = _generateIncrementNonceSaltSignature(signer, privateKey);
                vm.expectEmit(true, true, true, true);
                emit NonceSaltIncremented(signer, nextNonceSalt);
                multicallerWithSigner.incrementNonceSaltForSigner(signer, _maybeMake2098(signature));

                vm.expectRevert(MulticallerWithSigner.InvalidSignature.selector);
                multicallerWithSigner.incrementNonceSaltForSigner(signer, _maybeMake2098(signature));
            }
            uint256 nonceSaltAfter = multicallerWithSigner.nonceSaltOf(signer);
            assertEq(nextNonceSalt, nonceSaltAfter);
        }
    }

    function testMultiCallerWithSignerIncrementNonceSaltWithERC1271(uint256) public {
        _deployERC1271Contracts();
        uint256 nonceSaltBefore = multicallerWithSigner.nonceSaltOf(erc1271Wallet);
        uint256 nextNonceSalt = _nextNonceSalt(nonceSaltBefore);
        bytes memory signature =
            _generateIncrementNonceSaltSignature(erc1271Wallet, erc721SignerPrivateKey);

        vm.expectRevert(MulticallerWithSigner.InvalidSignature.selector);
        multicallerWithSigner.incrementNonceSaltForSigner(
            erc1271Malicious, _maybeMake2098(signature)
        );

        emit NonceSaltIncremented(erc1271Wallet, nextNonceSalt);
        multicallerWithSigner.incrementNonceSaltForSigner(erc1271Wallet, _maybeMake2098(signature));

        vm.expectRevert(MulticallerWithSigner.InvalidSignature.selector);
        multicallerWithSigner.incrementNonceSaltForSigner(erc1271Wallet, _maybeMake2098(signature));
    }

    function _generateInvalidateNoncesSignature(
        uint256[] memory nonces,
        address signer,
        uint256 privateKey
    ) internal view returns (bytes memory signature) {
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                _multicallerWithSignerDomainSeparator(),
                keccak256(
                    abi.encode(
                        keccak256(
                            "InvalidateNoncesForSigner(address signer,uint256[] nonces,uint256 nonceSalt)"
                        ),
                        signer,
                        keccak256(abi.encodePacked(nonces)),
                        multicallerWithSigner.nonceSaltOf(signer)
                    )
                )
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        signature = abi.encodePacked(r, s, v);
    }

    function _generateIncrementNonceSaltSignature(address signer, uint256 privateKey)
        internal
        view
        returns (bytes memory signature)
    {
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                _multicallerWithSignerDomainSeparator(),
                keccak256(
                    abi.encode(
                        keccak256("IncrementNonceSaltForSigner(address signer,uint256 nonceSalt)"),
                        signer,
                        multicallerWithSigner.nonceSaltOf(signer)
                    )
                )
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        signature = abi.encodePacked(r, s, v);
    }

    function _multicallerWithSignerDomainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256("MulticallerWithSigner"),
                keccak256("1"),
                block.chainid,
                address(multicallerWithSigner)
            )
        );
    }

    function _maybeMake2098(bytes memory signature)
        internal
        returns (bytes memory shortSignature)
    {
        if (_random() % 2 == 0 || signature.length != 65) {
            shortSignature = signature;
        } else {
            /// @solidity memory-safe-assembly
            assembly {
                let r := mload(add(signature, 0x20))
                let s := mload(add(signature, 0x40))
                let v := byte(0, mload(add(signature, 0x60)))
                shortSignature := mload(0x40)
                mstore(shortSignature, 0x40)
                mstore(add(shortSignature, 0x20), r)
                mstore(add(shortSignature, 0x40), or(shl(255, sub(v, 27)), s))
                mstore(0x40, add(shortSignature, 0x60))
            }
        }
    }

    function testOffsetTrick(uint256 a, uint256 b, uint256 c) public {
        unchecked {
            uint256 aDiff = a - c;
            uint256 bDiff = b - c;
            uint256 cPlus = c + 0x20;
            assertEq(cPlus + aDiff, a + 0x20);
            assertEq(cPlus + bDiff, b + 0x20);
        }
    }

    function revertsOnNastyCalldata(address[] calldata a) public pure returns (uint256) {
        return a.length;
    }

    function testNastyCalldataRevert() public {
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40)

            mstore(m, 0xcf74109c)
            mstore(add(m, 0x20), 0x20)
            mstore(add(m, 0x40), 1)
            mstore(add(m, 0x60), 0x112233)

            // Check does not revert with valid calldata.
            if iszero(call(gas(), address(), 0, add(m, 0x1c), 0x80, 0x00, 0x00)) {
                revert(0x00, 0x00)
            }

            // Check does not revert if address in array has dirty upper bits.
            // But don't worry, for Multicaller and MulticallerWithSender,
            // the `call` opcode can handle dirty upper bits.
            // For MulticallerWithSigner, it will revert, as the dirty bits will
            // corrupt the digest.
            mstore(add(m, 0x60), not(0))
            if iszero(call(gas(), address(), 0, add(m, 0x1c), 0x80, 0x00, 0x00)) {
                revert(0x00, 0x00)
            }
            mstore(add(m, 0x60), 0x112233)

            // Check reverts if length of array is excessive.
            mstore(add(m, 0x40), 2)
            if call(gas(), address(), 0, add(m, 0x1c), 0x80, 0x00, 0x00) { revert(0x00, 0x00) }

            // Check reverts if length of array is excessive.
            mstore(add(m, 0x40), shl(255, 1))
            if call(gas(), address(), 0, add(m, 0x1c), 0x80, 0x00, 0x00) { revert(0x00, 0x00) }

            // Check does not revert if array length is not excessive.
            let n := 20 // You can increase this and see that it will increase the gas spent.
            mstore(add(m, 0x40), n)
            if iszero(call(gas(), address(), 0, add(m, 0x1c), add(0x60, mul(n, 0x20)), 0x00, 0x00))
            {
                revert(0x00, 0x00)
            }
        }
    }

    function _cdCompress(bytes memory data) internal pure returns (bytes memory result) {
        /// @solidity memory-safe-assembly
        assembly {
            function rle(v_, o_, d_) -> _o, _d {
                mstore(o_, shl(240, or(and(0xff, add(d_, 0xff)), and(0x80, v_))))
                _o := add(o_, 2)
            }
            result := mload(0x40)
            let o := add(result, 0x20)
            let z := 0 // Number of consecutive 0x00.
            let y := 0 // Number of consecutive 0xff.
            for { let end := add(data, mload(data)) } iszero(eq(data, end)) {} {
                data := add(data, 1)
                let c := byte(31, mload(data))
                if iszero(c) {
                    if y { o, y := rle(0xff, o, y) }
                    z := add(z, 1)
                    if eq(z, 0x80) { o, z := rle(0x00, o, 0x80) }
                    continue
                }
                if eq(c, 0xff) {
                    if z { o, z := rle(0x00, o, z) }
                    y := add(y, 1)
                    if eq(y, 0x20) { o, y := rle(0xff, o, 0x20) }
                    continue
                }
                if y { o, y := rle(0xff, o, y) }
                if z { o, z := rle(0x00, o, z) }
                mstore8(o, c)
                o := add(o, 1)
            }
            if y { o, y := rle(0xff, o, y) }
            if z { o, z := rle(0x00, o, z) }
            // Bitwise negate the first 4 bytes.
            mstore(add(result, 4), not(mload(add(result, 4))))
            mstore(result, sub(o, add(result, 0x20))) // Store the length.
            mstore(o, 0) // Zeroize the slot after the string.
            mstore(0x40, add(o, 0x20)) // Allocate the memory.
        }
    }
}
