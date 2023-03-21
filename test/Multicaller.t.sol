// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "./utils/TestPlus.sol";
import {Multicaller} from "../src/Multicaller.sol";
import {MulticallerWithSender} from "../src/MulticallerWithSender.sol";
import {LibMulticaller} from "../src/LibMulticaller.sol";

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

    function name() external view returns (string memory) {
        return _name;
    }
}

/**
 * @dev This is an example to show how we can etch the multicaller onto
 *      `LibMulticaller.MULTICALLER` without copypastaing the initcode.
 */
contract MulticallerWithSenderUpgradeable is MulticallerWithSender {
    function initialize() external {
        assembly {
            sstore(0, shl(160, 1))
        }
    }
}

contract MulticallerTest is TestPlus {
    bytes public constant MULTICALLER_INITCODE =
        hex"60808060405234610016576101e8908161001c8239f35b600080fdfe6040608081526004908136101561001557600080fd5b600091823560e01c63b7402f641461002c57600080fd5b6060807ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126101785767ffffffffffffffff90823582811161017457610077903690850161017c565b92909160243582811161017057610091903690870161017c565b95909460443593841161016c576100ac87943690840161017c565b9490948114911416156101615750602090813d52858252851561015d57929460051b93919286929185838537858801955b84518401978a80848c85019b8035918291018d378b8a3585355af115610154577fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe091838080603f940199019782815201993d90523d8c8683013e3d010116928688101561014e5792969394966100dd565b8389018af35b8a3d81803e3d90fd5b863df35b633b800a463d52601cfd5b8880fd5b8780fd5b8580fd5b8380fd5b9181601f840112156101ad5782359167ffffffffffffffff83116101ad576020808501948460051b0101116101ad57565b600080fdfea26469706673582212204d6bae97f82dd3318e466a4e99ff28c87c6572d5112375dfc0954ef4c285402d64736f6c63430008120033";

    bytes32 public constant MULTICALLER_INITCODEHASH =
        0x27df471f370f0a7ae4e342d7d66a9820644c01f00c2ffdfa38672f6052809d8c;

    bytes32 public constant MULTICALLER_CREATE2_SALT =
        0x00000000000000000000000000000000000000002a612d11d8a18a00f7105ae8;

    address public constant MULTICALLER_CREATE2_DEPLOYED_ADDRESS =
        0x000000000088228fCF7b8af41Faf3955bD0B3A41;

    bytes public constant MULTICALLER_WITH_SENDER_INITCODE =
        hex"60806040819052600160a01b3d55610247908161001a8239f3fe60406080815260049081361015610023575b5050361561001e57600080fd5b6101f2565b600091823560e01c63d985f1e81461003b5750610011565b606090817ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126101b85767ffffffffffffffff81358181116101b45761008690369084016101bc565b916024358181116101b05761009e90369086016101bc565b9590936044359283116101ac576100b98793369088016101bc565b9390938114911416156101a0577401000000000000000000000000000000000000000094853d5416156101955750602090813d52868252861561019157333d55929560051b93919287929185838537858901955b84518401988b80848d85019c8d81359283920190378c8a3585355af115610188577fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe091838080603f9401990197828152019a3d90523d8d8683013e3d010116928689101561017f57929793949761010d565b878b55838a018bf35b8b3d81803e3d90fd5b873df35b63ab143c063d52601cfd5b84633b800a463d52601cfd5b8880fd5b8780fd5b8580fd5b8380fd5b9181601f840112156101ed5782359167ffffffffffffffff83116101ed576020808501948460051b0101116101ed57565b600080fd5b3d5473ffffffffffffffffffffffffffffffffffffffff163d5260203df3fea2646970667358221220802fc1f04a279628c77438e5942439f44c7eaf734a7dca754fef889a35be139764736f6c63430008120033";

    bytes32 public constant MULTICALLER_WITH_SENDER_INITCODEHASH =
        0xa89325c71cdfb4303b49efc3641eba7d01e0c220172e1b447366d7918606e04b;

    bytes32 public constant MULTICALLER_WITH_SENDER_CREATE2_SALT =
        0x00000000000000000000000000000000000000006bfa48b413e5be01a8e9fe0c;

    address public constant MULTICALLER_WITH_SENDER_CREATE2_DEPLOYED_ADDRESS =
        0x00000000002Fd5Aeb385D324B580FCa7c83823A0;

    Multicaller multicaller;
    MulticallerWithSender multicallerWithSender;

    MulticallerTarget targetA;
    MulticallerTarget targetB;

    function setUp() public virtual {
        {
            bytes32 salt = MULTICALLER_CREATE2_SALT;
            bytes memory initcode = MULTICALLER_INITCODE;
            address expectedDeployment = MULTICALLER_CREATE2_DEPLOYED_ADDRESS;
            multicaller = Multicaller(payable(_safeCreate2(salt, initcode)));
            assertEq(address(multicaller), expectedDeployment);
        }

        {
            bytes32 salt = MULTICALLER_WITH_SENDER_CREATE2_SALT;
            bytes memory initcode = MULTICALLER_WITH_SENDER_INITCODE;
            address expectedDeployment = MULTICALLER_WITH_SENDER_CREATE2_DEPLOYED_ADDRESS;
            multicallerWithSender = MulticallerWithSender(payable(_safeCreate2(salt, initcode)));
            assertEq(address(multicallerWithSender), expectedDeployment);
        }

        assertEq(LibMulticaller.MULTICALLER, MULTICALLER_CREATE2_DEPLOYED_ADDRESS);
        assertEq(
            LibMulticaller.MULTICALLER_WITH_SENDER, MULTICALLER_WITH_SENDER_CREATE2_DEPLOYED_ADDRESS
        );

        _deployTargets();
    }

    function _deployTargets() internal virtual {
        targetA = new MulticallerTarget("A");
        targetB = new MulticallerTarget("B");
    }

    function _etchMulticallerWithSender() internal virtual {
        multicallerWithSender =
            MulticallerWithSender(payable(LibMulticaller.MULTICALLER_WITH_SENDER));
        vm.etch(
            LibMulticaller.MULTICALLER_WITH_SENDER,
            bytes(address(new MulticallerWithSenderUpgradeable()).code)
        );
        MulticallerWithSenderUpgradeable(payable(LibMulticaller.MULTICALLER_WITH_SENDER)).initialize(
        );
    }

    modifier onMulticallers() {
        for (uint256 t; t != 2; ++t) {
            _;
            assertEq(LibMulticaller.multicallerSender(), address(0));
            _etchMulticallerWithSender();
            _deployTargets();
        }
    }

    function testMulticallerRevertWithMessage(string memory revertMessage) public onMulticallers {
        address[] memory targets = new address[](1);
        targets[0] = address(targetA);
        bytes[] memory data = new bytes[](1);
        data[0] =
            abi.encodeWithSelector(MulticallerTarget.revertsWithString.selector, revertMessage);
        vm.expectRevert(bytes(revertMessage));
        multicaller.aggregate(targets, data, new uint256[](1));
        vm.expectRevert(bytes(revertMessage));
        multicallerWithSender.aggregateWithSender(targets, data, new uint256[](1));
    }

    function testMulticallerRevertWithMessage() public {
        testMulticallerRevertWithMessage("Milady");
    }

    function testMulticallerRevertWithCustomError() public onMulticallers {
        address[] memory targets = new address[](1);
        targets[0] = address(targetA);
        bytes[] memory data = new bytes[](1);
        data[0] = abi.encodeWithSelector(MulticallerTarget.revertsWithCustomError.selector);
        vm.expectRevert(MulticallerTarget.CustomError.selector);
        multicaller.aggregate(targets, data, new uint256[](1));
        vm.expectRevert(MulticallerTarget.CustomError.selector);
        multicallerWithSender.aggregateWithSender(targets, data, new uint256[](1));
    }

    function testMulticallerRevertWithNothing() public onMulticallers {
        address[] memory targets = new address[](1);
        targets[0] = address(targetA);
        bytes[] memory data = new bytes[](1);
        data[0] = abi.encodeWithSelector(MulticallerTarget.revertsWithNothing.selector);
        vm.expectRevert();
        multicaller.aggregate(targets, data, new uint256[](1));
        vm.expectRevert();
        multicallerWithSender.aggregateWithSender(targets, data, new uint256[](1));
    }

    function testMulticallerReturnDataIsProperlyEncoded(
        uint256 a0,
        uint256 b0,
        uint256 a1,
        uint256 b1
    ) public onMulticallers {
        address[] memory targets = new address[](2);
        targets[0] = address(targetA);
        targets[1] = address(targetB);
        bytes[] memory data = new bytes[](2);
        data[0] = abi.encodeWithSelector(MulticallerTarget.returnsTuple.selector, a0, b0);
        data[1] = abi.encodeWithSelector(MulticallerTarget.returnsTuple.selector, a1, b1);
        bytes[] memory results = multicaller.aggregate(targets, data, new uint256[](2));
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
    ) public onMulticallers {
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
        bytes[] memory results = multicaller.aggregate(targets, data, new uint256[](n));
        for (uint256 i; i != n; ++i) {
            string memory s = choices[i] == 0 ? s0 : s1;
            assertEq(abi.decode(results[i], (string)), s);
        }
        assertEq(
            abi.encode(multicallerWithSender.aggregateWithSender(targets, data, new uint256[](n))),
            abi.encode(results)
        );
    }

    function testMulticallerReturnDataIsProperlyEncoded() public {
        testMulticallerReturnDataIsProperlyEncoded(0, 1, 2, 3);
    }

    function testMulticallerWithNoData() public onMulticallers {
        address[] memory targets = new address[](0);
        bytes[] memory data = new bytes[](0);
        assertEq(multicaller.aggregate(targets, data, new uint256[](0)).length, 0);
        assertEq(
            multicallerWithSender.aggregateWithSender(targets, data, new uint256[](0)).length, 0
        );
    }

    function testMulticallerForwardsMessageValue() public onMulticallers {
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
        multicaller.aggregate{value: 4}(targets, data, values);
        multicallerWithSender.aggregateWithSender{value: 4}(targets, data, values);
        assertEq(targetA.paid(), 2);
        assertEq(targetB.paid(), 6);

        targets[0] = address(targetB);
        targets[1] = address(targetB);
        targets[2] = address(targetA);
        targets[3] = address(targetA);
        values[0] = 0;
        values[3] = 5;
        multicaller.aggregate{value: 5}(targets, data, values);
        multicallerWithSender.aggregateWithSender{value: 5}(targets, data, values);
        assertEq(targetA.paid(), 12);
        assertEq(targetB.paid(), 6);

        targets = new address[](1);
        targets[0] = address(targetA);
        data = new bytes[](1);
        data[0] = abi.encodeWithSelector(MulticallerTarget.pay.selector);
        values = new uint256[](1);
        values[0] = 3;
        multicaller.aggregate{value: 3}(targets, data, values);
        multicallerWithSender.aggregateWithSender{value: 3}(targets, data, values);
        assertEq(targetA.paid(), 18);
    }

    function testMulticallerGetNames() public onMulticallers {
        address[] memory targets = new address[](2);
        targets[0] = address(targetA);
        targets[1] = address(targetB);
        bytes[] memory data = new bytes[](2);
        data[0] = abi.encodeWithSelector(MulticallerTarget.name.selector);
        data[1] = abi.encodeWithSelector(MulticallerTarget.name.selector);
        bytes[] memory results = multicaller.aggregate(targets, data, new uint256[](2));
        assertEq(abi.decode(results[0], (string)), "A");
        assertEq(abi.decode(results[1], (string)), "B");
        assertEq(
            abi.encode(multicallerWithSender.aggregateWithSender(targets, data, new uint256[](2))),
            abi.encode(results)
        );
    }

    function testMulticallerReentrancyGuard() public onMulticallers {
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

    function testMulticallerTargetGetMulticallerSender() public onMulticallers {
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
    }

    function testMulticallerSenderDoesNotRevertWithoutMulticallerDeployed() public {
        vm.etch(LibMulticaller.MULTICALLER_WITH_SENDER, "");
        assertEq(LibMulticaller.multicallerSender(), address(0));
    }
}
