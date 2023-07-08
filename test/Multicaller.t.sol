// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "./utils/TestPlus.sol";
import {Multicaller} from "../src/Multicaller.sol";
import {MulticallerWithSender} from "../src/MulticallerWithSender.sol";
import {MulticallerWithSigner} from "../src/MulticallerWithSigner.sol";
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

    bytes public constant MULTICALLER_WITH_SIGNER_INITCODE =
        hex"6080806040523060a01b3d5561086090816100188239f3fe6080604052600480361015610020575b50361561001b57600080fd5b610569565b6000803560e01c9182630f902fba1461009a575050806313707df31461009557806317447cf1146100905780632eb48a801461008b5780633aeb22061461008657806384b0196e146100815763f0c60f1a1461007c573861000f565b610512565b610443565b6103dc565b610341565b6102c2565b610287565b6101003660031901126101555767ffffffffffffffff918135838111610155576100c79036908401610194565b91602435848111610151576100df90369083016101fc565b93909160443586811161014d576100f990369083016101fc565b6064979197358281116101495761011390369085016101fc565b93909261011e61022d565b9760e435918211610146575061013691369101610259565b98909760a435966084359661057b565b80fd5b8680fd5b8480fd5b8280fd5b5080fd5b634e487b7160e01b600052604160045260246000fd5b604051906040820182811067ffffffffffffffff82111761018f57604052565b610159565b81601f820112156101f75780359067ffffffffffffffff9283831161018f5760405193601f8401601f19908116603f011685019081118582101761018f57604052828452602083830101116101f757816000926020809301838601378301015290565b600080fd5b9181601f840112156101f75782359167ffffffffffffffff83116101f7576020808501948460051b0101116101f757565b60c435906001600160a01b03821682036101f757565b600435906001600160a01b03821682036101f757565b9181601f840112156101f75782359167ffffffffffffffff83116101f757602083818601950101116101f757565b346101f75760003660031901126101f75760206040517fc4d2f044d99707794280032fc14879a220a3f7dc766d75100809624f91d69e978152f35b346101f7576040806003193601126101f7576102dc610243565b9060243567ffffffffffffffff81116101f7576102fd9036906004016101fc565b90923d528060051b923d5b84810361031c57505060203d52602052013df35b806020918301358060081c83526034600c20549060ff161c6001168186015201610308565b346101f7576020806003193601126101f75760043567ffffffffffffffff81116101f7576103739036906004016101fc565b90333d528160051b913d5b8381036103b957508383943d52526040377fc45e3a0dd412bcad8d62398d74d66b1c8449f38beb10da275e4da0c6d3a811a433916040013da2005b8085918401358060081c835260016034600c209160ff161b81541790550161037e565b346101f75760203660031901126101f75760016103f7610243565b60601b17543d5260203df35b919082519283825260005b84811061042f575050826000602080949584010152601f8019910116010190565b60208183018101518483018201520161040e565b346101f75760003660031901126101f75761045c61016f565b601581526020907426bab63a34b1b0b63632b92bb4ba3429b4b3b732b960591b8282015261048861016f565b6104c6600191828152603160f81b858201526104b860405194600f60f81b865260e08787015260e0860190610403565b908482036040860152610403565b92466060840152306080840152600060a084015282840360c08401528060605194858152019360809160005b8281106104ff5785870386f35b83518752958101959281019284016104f2565b346101f75760003660031901126101f75760013360601b176001815460001943014060e01c01018091553d52337f997a42216df16c8b9e7caf2fc71c59dba956f1f2b12320f87a80a5879464217d60203da260203df35b3d546001600160a01b03163d5260203df35b969a9890949593979291976060948114818a14161561081d573d5460a01c156108105760059997991b987fc4d2f044d99707794280032fc14879a220a3f7dc766d75100809624f91d69e973d52805197602098898093012082528a8d60409d8e91838b843783832083523d5b8481036107e55750838a208a52608093808d86378420845260a0528760c05260e03d2082527f8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f83527f301013e8a31863902646dc218ecd889c37491c2967a8104d5ff1cf42af0f9ea460a0527fc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc660c0524660e05230610100526119013d5260a0832085526042601e203d52818101353d1a855281373d913d9060417f7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a18a51109114165afa5060009a818c51143d0293828d528160081c89526034600c20908154600196878560ff161b9288878b1b175418828416179015176107d857179055878c528388528a52807fc45e3a0dd412bcad8d62398d74d66b1c8449f38beb10da275e4da0c6d3a811a4858da288156107d1578295918a918c969594965581928a8284378a83019590965b610765575b8989523060a01b8d558a83018df35b8c808a869798999a9d949596518601968501968035918291018837868b3585355af1156107c857888080920198019482815201923d90523d8c8683013e3d01603f01601f1916988286146107c15795908a918796959496610751565b8a91610756565b8c3d81803e3d90fd5b898b8a8952f35b638baa579f8f526004601cfd5b9250509293915080860135860182828a0191803591829101833781209052018c8a93928f8e936105e7565b63ab143c063d526004601cfd5b633b800a463d526004601cfdfea2646970667358221220004f3a20d07c0c590889750bf7f97a0a18b3f5df95c9a39806898163302a854764736f6c63430008120033";

    bytes32 public constant MULTICALLER_WITH_SIGNER_INITCODEHASH =
        0x55306d564b596aa0fb7d2dd1299d7df4380a3d717d9ec2cd608cbeb9f2a4513b;

    bytes32 public constant MULTICALLER_WITH_SIGNER_CREATE2_SALT =
        0x0000000000000000000000000000000000000000b21e607889e3e2005f84a281;

    address public constant MULTICALLER_WITH_SIGNER_CREATE2_DEPLOYED_ADDRESS =
        0x000000000000B06107881d4b55B76Cee8DeC3728;

    Multicaller multicaller;
    MulticallerWithSender multicallerWithSender;
    MulticallerWithSigner multicallerWithSigner;

    MulticallerTarget targetA;
    MulticallerTarget targetB;

    FallbackTarget fallbackTargetA;
    FallbackTarget fallbackTargetB;

    event NoncesInvalidated(address indexed signer, uint256[] nonces);

    event NonceSaltIncremented(address indexed signer, uint256 newNonceSalt);

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

        {
            bytes32 salt = MULTICALLER_WITH_SIGNER_CREATE2_SALT;
            bytes memory initcode = MULTICALLER_WITH_SIGNER_INITCODE;
            address expectedDeployment = MULTICALLER_WITH_SIGNER_CREATE2_DEPLOYED_ADDRESS;
            multicallerWithSigner = MulticallerWithSigner(payable(_safeCreate2(salt, initcode)));
            assertEq(address(multicallerWithSigner), expectedDeployment);
        }

        assertEq(LibMulticaller.MULTICALLER, MULTICALLER_CREATE2_DEPLOYED_ADDRESS);
        assertEq(
            LibMulticaller.MULTICALLER_WITH_SENDER, MULTICALLER_WITH_SENDER_CREATE2_DEPLOYED_ADDRESS
        );
        assertEq(
            LibMulticaller.MULTICALLER_WITH_SIGNER, MULTICALLER_WITH_SIGNER_CREATE2_DEPLOYED_ADDRESS
        );

        _deployTargets();
    }

    function _deployTargets() internal virtual {
        targetA = new MulticallerTarget("A");
        targetB = new MulticallerTarget("B");
        fallbackTargetA = new FallbackTarget();
        fallbackTargetB = new FallbackTarget();
    }

    function testMulticallerRevertWithMessage(string memory revertMessage) public {
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

    function testMulticallerRevertWithCustomError() public {
        address[] memory targets = new address[](1);
        targets[0] = address(targetA);
        bytes[] memory data = new bytes[](1);
        data[0] = abi.encodeWithSelector(MulticallerTarget.revertsWithCustomError.selector);
        vm.expectRevert(MulticallerTarget.CustomError.selector);
        multicaller.aggregate(targets, data, new uint256[](1));
        vm.expectRevert(MulticallerTarget.CustomError.selector);
        multicallerWithSender.aggregateWithSender(targets, data, new uint256[](1));
    }

    function testMulticallerRevertWithNothing() public {
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
    ) public {
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

    function testMulticallerWithNoData() public {
        address[] memory targets = new address[](0);
        bytes[] memory data = new bytes[](0);
        assertEq(multicaller.aggregate(targets, data, new uint256[](0)).length, 0);
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

    function testMulticallerGetNames() public {
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
        string message;
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

    function _generateSignature(_TestTemps memory t) internal {
        unchecked {
            bytes32[] memory dataHashes = new bytes32[](t.data.length);
            for (uint256 i; i < t.data.length; ++i) {
                dataHashes[i] = keccak256(t.data[i]);
            }
            bytes32 digest = keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    keccak256(
                        abi.encode(
                            keccak256(
                                "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                            ),
                            keccak256("MulticallerWithSigner"),
                            keccak256("1"),
                            block.chainid,
                            address(multicallerWithSigner)
                        )
                    ),
                    keccak256(
                        abi.encode(
                            keccak256(
                                "AggregateWithSigner(string message,address[] targets,bytes[] data,uint256[] values,uint256 nonce,uint256 nonceSalt)"
                            ),
                            keccak256(abi.encodePacked(t.message)),
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
        t.message = string(_randomBytes());
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

    function _callMulticallerWithSigner(_TestTemps memory t, uint256 value)
        internal
        returns (bytes[] memory results)
    {
        results = multicallerWithSigner.aggregateWithSigner{value: value}(
            string(t.message),
            t.targets,
            t.data,
            t.values,
            t.nonce,
            t.nonceSalt,
            t.signer,
            t.signature
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

            (address signer,) = _randomSigner();

            bool[] memory invalidated = multicallerWithSigner.noncesInvalidated(signer, nonces);
            for (uint256 i; i < nonces.length; ++i) {
                assertEq(invalidated[i], false);
            }

            vm.prank(signer);
            vm.expectEmit(true, true, true, true);
            emit NoncesInvalidated(signer, nonces);
            multicallerWithSigner.invalidateNonces(nonces);

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

    function testNastyCalldataRevert() public {
        assembly {
            let m := mload(0x40)
            mstore(m, 0x2eb48a80)
            mstore(add(m, 0x20), 0x20)
            mstore(add(m, 0x40), 1)
            mstore(add(m, 0x60), 0x112233)
            if iszero(
                call(gas(), sload(multicallerWithSigner.slot), 0, add(m, 0x1c), 0x80, 0x00, 0x00)
            ) { revert(0x00, 0x00) }
            mstore(add(m, 0x40), 2)
            if call(gas(), sload(multicallerWithSigner.slot), 0, add(m, 0x1c), 0x80, 0x00, 0x00) {
                revert(0x00, 0x00)
            }
            mstore(add(m, 0x40), shl(255, 1))
            if call(gas(), sload(multicallerWithSigner.slot), 0, add(m, 0x1c), 0x80, 0x00, 0x00) {
                revert(0x00, 0x00)
            }
        }
    }
}
