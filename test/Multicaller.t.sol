// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "./utils/TestPlus.sol";
import {Multicaller} from "../src/Multicaller.sol";
import {MulticallerReader} from "../src/MulticallerReader.sol";

interface IImmutableCreate2Factory {
    function safeCreate2(bytes32 salt, bytes calldata initializationCode)
        external
        payable
        returns (address deploymentAddress);
}

contract MulticallerTarget {
    error CustomError();

    Multicaller private _multicaller;

    string private _name;

    constructor(Multicaller multicaller_, string memory name_) {
        _multicaller = multicaller_;
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
        return msg.sender;
    }

    function returnsMulticallerSender() external view returns (address) {
        return MulticallerReader.sender();
    }

    function name() external view returns (string memory) {
        return _name;
    }
}

contract MulticallerTest is TestPlus {
    bytes public constant IMMUTABLE_CREATE2_FACTORY_BYTECODE =
        hex"60806040526004361061003f5760003560e01c806308508b8f1461004457806364e030871461009857806385cf97ab14610138578063a49a7c90146101bc575b600080fd5b34801561005057600080fd5b506100846004803603602081101561006757600080fd5b503573ffffffffffffffffffffffffffffffffffffffff166101ec565b604080519115158252519081900360200190f35b61010f600480360360408110156100ae57600080fd5b813591908101906040810160208201356401000000008111156100d057600080fd5b8201836020820111156100e257600080fd5b8035906020019184600183028401116401000000008311171561010457600080fd5b509092509050610217565b6040805173ffffffffffffffffffffffffffffffffffffffff9092168252519081900360200190f35b34801561014457600080fd5b5061010f6004803603604081101561015b57600080fd5b8135919081019060408101602082013564010000000081111561017d57600080fd5b82018360208201111561018f57600080fd5b803590602001918460018302840111640100000000831117156101b157600080fd5b509092509050610592565b3480156101c857600080fd5b5061010f600480360360408110156101df57600080fd5b508035906020013561069e565b73ffffffffffffffffffffffffffffffffffffffff1660009081526020819052604090205460ff1690565b600083606081901c33148061024c57507fffffffffffffffffffffffffffffffffffffffff0000000000000000000000008116155b6102a1576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260458152602001806107746045913960600191505060405180910390fd5b606084848080601f0160208091040260200160405190810160405280939291908181526020018383808284376000920182905250604051855195965090943094508b93508692506020918201918291908401908083835b6020831061033557805182527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe090920191602091820191016102f8565b51815160209384036101000a7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff018019909216911617905260408051929094018281037fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe00183528085528251928201929092207fff000000000000000000000000000000000000000000000000000000000000008383015260609890981b7fffffffffffffffffffffffffffffffffffffffff00000000000000000000000016602183015260358201969096526055808201979097528251808203909701875260750182525084519484019490942073ffffffffffffffffffffffffffffffffffffffff81166000908152938490529390922054929350505060ff16156104a7576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252603f815260200180610735603f913960400191505060405180910390fd5b81602001825188818334f5955050508073ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff161461053a576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260468152602001806107b96046913960600191505060405180910390fd5b50505073ffffffffffffffffffffffffffffffffffffffff8116600090815260208190526040902080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff001660011790559392505050565b6000308484846040516020018083838082843760408051919093018181037fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe001825280845281516020928301207fff000000000000000000000000000000000000000000000000000000000000008383015260609990991b7fffffffffffffffffffffffffffffffffffffffff000000000000000000000000166021820152603581019790975260558088019890985282518088039098018852607590960182525085519585019590952073ffffffffffffffffffffffffffffffffffffffff81166000908152948590529490932054939450505060ff909116159050610697575060005b9392505050565b604080517fff000000000000000000000000000000000000000000000000000000000000006020808301919091523060601b6021830152603582018590526055808301859052835180840390910181526075909201835281519181019190912073ffffffffffffffffffffffffffffffffffffffff81166000908152918290529190205460ff161561072e575060005b9291505056fe496e76616c696420636f6e7472616374206372656174696f6e202d20636f6e74726163742068617320616c7265616479206265656e206465706c6f7965642e496e76616c69642073616c74202d206669727374203230206279746573206f66207468652073616c74206d757374206d617463682063616c6c696e6720616464726573732e4661696c656420746f206465706c6f7920636f6e7472616374207573696e672070726f76696465642073616c7420616e6420696e697469616c697a6174696f6e20636f64652ea265627a7a723058202bdc55310d97c4088f18acf04253db593f0914059f0c781a9df3624dcef0d1cf64736f6c634300050a0032";

    address public constant IMMUTABLE_CREATE2_FACTORY_ADDRESS =
        0x0000000000FFe8B47B3e2130213B802212439497;

    bytes public constant MULTICALLER_INITCODE =
        hex"60806040819052600160a01b600055610331908161001b8239f3fe604060808152600436101561001357600080fd5b6000803560e01c918263269d64ae1461004c575050806367e404ce146100475763915b64e21461004257600080fd5b610202565b6101b0565b61005536610147565b8091920361010457602092838652818452811561010057929190849060051b918281873782938734948801955b818084875187018c850199818b92359384910183378c355af1156100f757603f7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0918480859b019782815201973d90523d84606083013e3d01011692868610156100f0579396949392610082565b5087830190f35b503d81803e3d90fd5b8486f35b633b800a4685526004601cfd5b9181601f840112156101425782359167ffffffffffffffff8311610142576020808501948460051b01011161014257565b600080fd5b60407ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc8201126101425767ffffffffffffffff91600435838111610142578261019291600401610111565b93909392602435918211610142576101ac91600401610111565b9091565b34610142576000807ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126101ff57806020915473ffffffffffffffffffffffffffffffffffffffff168152f35b80fd5b61020b36610147565b9290918390036102ed57740100000000000000000000000000000000000000009160009383855416156102e05733855560209283865281845281156102db5792919060409060051b918281833782938734948401955b818084875187016040850199818b92359384910183378c355af1156100f757603f7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0918480859b019782815201973d90523d84606083013e3d01011692868610156102d0579396949392610261565b506040838983550190f35b604086f35b63ab143c0685526004601cfd5b633b800a466000526004601cfdfea2646970667358221220361324acc35acb26ed6e4ca9f66b9e8f21c556287fb7ea22ef2e2f4eb9749c9c64736f6c63430008120033";

    bytes32 public constant MULTICALLER_INITCODEHASH =
        0x3324079a1840156eeb13f064eb7754ce64967d4456e4c69a25c13c9c01a61d79;

    bytes32 public constant MULTICALLER_CREATE2_SALT =
        0x0000000000000000000000000000000000000000253f417a962bcd0203ba8e5e;

    address public constant MULTICALLER_CREATE2_DEPLOYED_ADDRESS =
        0x0000000000Fe5181175f102CF3a152347FFB69Cd;

    Multicaller multicaller;

    MulticallerTarget targetA;
    MulticallerTarget targetB;

    function setUp() public virtual {
        vm.etch(IMMUTABLE_CREATE2_FACTORY_ADDRESS, bytes(IMMUTABLE_CREATE2_FACTORY_BYTECODE));
        IImmutableCreate2Factory c2f = IImmutableCreate2Factory(IMMUTABLE_CREATE2_FACTORY_ADDRESS);

        bytes32 salt = MULTICALLER_CREATE2_SALT;
        bytes memory initcode = MULTICALLER_INITCODE;
        address expectedDeployment = MULTICALLER_CREATE2_DEPLOYED_ADDRESS;
        multicaller = Multicaller(c2f.safeCreate2(salt, initcode));
        assertEq(address(multicaller), expectedDeployment);

        targetA = new MulticallerTarget(multicaller, "A");
        targetB = new MulticallerTarget(multicaller, "B");
    }

    function testMulticallerRevertWithMessage(string memory revertMessage) public {
        address[] memory targets = new address[](1);
        targets[0] = address(targetA);
        bytes[] memory data = new bytes[](1);
        data[0] =
            abi.encodeWithSelector(MulticallerTarget.revertsWithString.selector, revertMessage);
        vm.expectRevert(bytes(revertMessage));
        multicaller.aggregate(targets, data);
        vm.expectRevert(bytes(revertMessage));
        multicaller.aggregateWithSender(targets, data);
        assertEq(multicaller.sender(), address(0));
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
        multicaller.aggregate(targets, data);
        vm.expectRevert(MulticallerTarget.CustomError.selector);
        multicaller.aggregateWithSender(targets, data);
        assertEq(multicaller.sender(), address(0));
    }

    function testMulticallerRevertWithNothing() public {
        address[] memory targets = new address[](1);
        targets[0] = address(targetA);
        bytes[] memory data = new bytes[](1);
        data[0] = abi.encodeWithSelector(MulticallerTarget.revertsWithNothing.selector);
        vm.expectRevert();
        multicaller.aggregate(targets, data);
        vm.expectRevert();
        multicaller.aggregateWithSender(targets, data);
        assertEq(multicaller.sender(), address(0));
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
        bytes[] memory results = multicaller.aggregate(targets, data);
        MulticallerTarget.Tuple memory t0 = abi.decode(results[0], (MulticallerTarget.Tuple));
        MulticallerTarget.Tuple memory t1 = abi.decode(results[1], (MulticallerTarget.Tuple));
        assertEq(t0.a, a0);
        assertEq(t0.b, b0);
        assertEq(t1.a, a1);
        assertEq(t1.b, b1);
        assertEq(abi.encode(multicaller.aggregateWithSender(targets, data)), abi.encode(results));
    }

    function testMulticallerReturnDataIsProperlyEncoded(
        string memory sIn0,
        string memory sIn1,
        uint256 n
    ) public {
        n = n % 2;
        address[] memory targets = new address[](n);
        bytes[] memory data = new bytes[](n);
        if (n > 0) {
            data[0] = abi.encodeWithSelector(MulticallerTarget.returnsString.selector, sIn0);
            targets[0] = address(targetA);
        }
        if (n > 1) {
            data[1] = abi.encodeWithSelector(MulticallerTarget.returnsString.selector, sIn1);
            targets[1] = address(targetB);
        }
        bytes[] memory results = multicaller.aggregate(targets, data);
        if (n > 0) {
            assertEq(abi.decode(results[0], (string)), sIn0);
        }
        if (n > 1) {
            assertEq(abi.decode(results[1], (string)), sIn1);
        }
        assertEq(abi.encode(multicaller.aggregateWithSender(targets, data)), abi.encode(results));
    }

    function testMulticallerReturnDataIsProperlyEncoded() public {
        testMulticallerReturnDataIsProperlyEncoded(0, 1, 2, 3);
    }

    function testMulticallerWithNoData() public {
        address[] memory targets = new address[](0);
        bytes[] memory data = new bytes[](0);
        assertEq(multicaller.aggregate(targets, data).length, 0);
        assertEq(multicaller.aggregateWithSender(targets, data).length, 0);
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
        multicaller.aggregate{value: 3}(targets, data);
        assertEq(targetA.paid(), 3);
        assertEq(targetB.paid(), 0);
        targets[0] = address(targetB);
        targets[1] = address(targetB);
        targets[2] = address(targetA);
        targets[3] = address(targetA);
        multicaller.aggregate{value: 3}(targets, data);
        assertEq(targetA.paid(), 3);
        assertEq(targetB.paid(), 3);
    }

    function testMulticallerGetNames() public {
        address[] memory targets = new address[](2);
        targets[0] = address(targetA);
        targets[1] = address(targetB);
        bytes[] memory data = new bytes[](2);
        data[0] = abi.encodeWithSelector(MulticallerTarget.name.selector);
        data[1] = abi.encodeWithSelector(MulticallerTarget.name.selector);
        bytes[] memory results = multicaller.aggregate(targets, data);
        assertEq(abi.decode(results[0], (string)), "A");
        assertEq(abi.decode(results[1], (string)), "B");
        assertEq(abi.encode(multicaller.aggregateWithSender(targets, data)), abi.encode(results));
    }

    function testMulticallerReentrancyGuard() public {
        address[] memory targets = new address[](1);
        targets[0] = address(multicaller);
        bytes[] memory data = new bytes[](1);
        data[0] = abi.encodeWithSelector(
            Multicaller.aggregateWithSender.selector, new address[](0), new bytes[](0)
        );
        vm.expectRevert(Multicaller.Reentrancy.selector);
        multicaller.aggregateWithSender(targets, data);
        assertEq(multicaller.sender(), address(0));
    }

    function testMulticallerTargetGetMulticallerSender() public {
        address[] memory targets = new address[](1);
        targets[0] = address(targetA);
        bytes[] memory data = new bytes[](1);
        data[0] = abi.encodeWithSelector(MulticallerTarget.returnsMulticallerSender.selector);
        bytes[] memory results = multicaller.aggregateWithSender(targets, data);
        assertEq(abi.decode(results[0], (address)), address(this));
        data[0] = abi.encodeWithSelector(MulticallerTarget.returnsSender.selector);
        results = multicaller.aggregateWithSender(targets, data);
        assertEq(abi.decode(results[0], (address)), address(multicaller));
        data[0] = abi.encodeWithSelector(MulticallerTarget.returnsMulticallerSender.selector);
        results = multicaller.aggregate(targets, data);
        assertEq(abi.decode(results[0], (address)), address(0));
        data[0] = abi.encodeWithSelector(MulticallerTarget.returnsSender.selector);
        results = multicaller.aggregate(targets, data);
        assertEq(abi.decode(results[0], (address)), address(multicaller));
        assertEq(multicaller.sender(), address(0));
    }
}
