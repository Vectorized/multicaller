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
        hex"60808060405234610016576102e1908161001c8239f35b600080fdfe60806040526004361015610015575b3661022557005b6000803560e01c63991f255f1461002c575061000e565b60803660031901126100aa5767ffffffffffffffff6004358181116100b5576100599036906004016100b9565b916024358181116100b1576100729036906004016100b9565b916044359081116100ad5761008b9036906004016100b9565b6064359690959194906001600160a01b03881688036100aa575061013d565b80fd5b8580fd5b8480fd5b8280fd5b9181601f840112156100ea5782359167ffffffffffffffff83116100ea576020808501948460051b0101116100ea57565b600080fd5b471561012d57338118600182140218600090818080804785620186a0f115610115575050565b81526073600b5360ff6020536016600b47f015610130575b50565b620f42405a1161012d5780fd5b9093919294606090861486861416156102185785156101f257929460051b9260409184878437848301945b83518801906040810182359081602080950182376000808093838a8c603f19918291010135908c8b0101355af1156101e9578287523d90523d908583013e603f601f19913d0101169301968588146101c1579692610168565b604084888b806101da575b506020600052602052016000f35b6101e3906100ef565b836101cc565b503d81803e3d90fd5b848780610209575b50602060005260205260406000f35b610212906100ef565b816101fa565b633b800a463d526004601cfd5b3d356366e0daa08160e01c14610239573d3dfd5b193d5260043d815b36811061026257600080808581305af43d82803e1561025e573d90f35b3d90fd5b8035821a92600180920193801561027f57815301905b9091610241565b503d19815283820193607f90353d1a818111156102a0575b16010190610278565b83810138843961029756fea26469706673582212208717cbf85b21fbcaee8728232250ef65345aa0ba543377c9dfcacaff743c677c64736f6c63430008120033";

    bytes32 public constant MULTICALLER_INITCODEHASH =
        0x2fb4b1c29ca72b22a1d4ab7b9397743ad2efb338f4a118e83552dda5f547a976;

    bytes32 public constant MULTICALLER_CREATE2_SALT =
        0x00000000000000000000000000000000000000000ea5ca7862f5ba0059d5c780;

    address public constant MULTICALLER_CREATE2_DEPLOYED_ADDRESS =
        0x0000000000009C27972b97d86134DFcffACAbE15;

    bytes public constant MULTICALLER_WITH_SENDER_INITCODE =
        hex"60806040819052600160a01b3d55610247908161001a8239f3fe60406080815260049081361015610023575b5050361561001e57600080fd5b6101f2565b600091823560e01c63d985f1e81461003b5750610011565b606090817ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126101b85767ffffffffffffffff81358181116101b45761008690369084016101bc565b916024358181116101b05761009e90369086016101bc565b9590936044359283116101ac576100b98793369088016101bc565b9390938114911416156101a0577401000000000000000000000000000000000000000094853d5416156101955750602090813d52868252861561019157333d55929560051b93919287929185838537858901955b84518401988b80848d85019c8d81359283920190378c8a3585355af115610188577fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe091838080603f9401990197828152019a3d90523d8d8683013e3d010116928689101561017f57929793949761010d565b878b55838a018bf35b8b3d81803e3d90fd5b873df35b63ab143c063d52601cfd5b84633b800a463d52601cfd5b8880fd5b8780fd5b8580fd5b8380fd5b9181601f840112156101ed5782359167ffffffffffffffff83116101ed576020808501948460051b0101116101ed57565b600080fd5b3d5473ffffffffffffffffffffffffffffffffffffffff163d5260203df3fea2646970667358221220802fc1f04a279628c77438e5942439f44c7eaf734a7dca754fef889a35be139764736f6c63430008120033";

    bytes32 public constant MULTICALLER_WITH_SENDER_INITCODEHASH =
        0xa89325c71cdfb4303b49efc3641eba7d01e0c220172e1b447366d7918606e04b;

    bytes32 public constant MULTICALLER_WITH_SENDER_CREATE2_SALT =
        0x00000000000000000000000000000000000000006bfa48b413e5be01a8e9fe0c;

    address public constant MULTICALLER_WITH_SENDER_CREATE2_DEPLOYED_ADDRESS =
        0x00000000002Fd5Aeb385D324B580FCa7c83823A0;

    bytes public constant MULTICALLER_WITH_SIGNER_INITCODE =
        hex"6080806040523060a01b3d55610b6f90816100188239f3fe6040608081526004361015610020575b50361561001b57600080fd5b61089c565b6000803560e01c91826317447cf1146100aa57505080632eb48a80146100a55780633aeb2206146100a05780634eb311501461009b57806356b1a87f1461009657806384b0196e1461009157806387ec11ca1461008c5763f0c60f1a14610087573861000f565b610845565b610673565b6105a4565b6103de565b610337565b610244565b6101a9565b3461012d578060031936011261012d576100c2610131565b916024359067ffffffffffffffff821161012a57506100e5903690600401610178565b90923d528060051b923d3d905b8581036101075750505060203d52602052013df35b806020918401358060081c8352868420549060ff161c60011681870152016100f2565b80fd5b5080fd5b600435906001600160a01b038216820361014757565b600080fd5b60a435906001600160a01b038216820361014757565b602435906001600160a01b038216820361014757565b9181601f840112156101475782359167ffffffffffffffff8311610147576020808501948460051b01011161014757565b34610147576020806003193601126101475760043567ffffffffffffffff8111610147576101db903690600401610178565b90333d528160051b913d3d905b8481036102245750508383943d52526040377fc45e3a0dd412bcad8d62398d74d66b1c8449f38beb10da275e4da0c6d3a811a433916040013da2005b808691850135806021526001604085209160ff161b8154179055016101e8565b3461014757602036600319011261014757600161025f610131565b60601b17543d5260203df35b634e487b7160e01b600052604160045260246000fd5b604051906040820182811067ffffffffffffffff8211176102a157604052565b61026b565b81601f820112156101475780359067ffffffffffffffff928383116102a15760405193601f8401601f19908116603f01168501908111858210176102a1576040528284526020838301011161014757816000926020809301838601378301015290565b9181601f840112156101475782359167ffffffffffffffff8311610147576020838186019501011161014757565b60e036600319011261014757600467ffffffffffffffff81358181116101475761036490369084016102a6565b916024358281116101475761037c9036908301610178565b939092604435818111610147576103969036908501610178565b606492919235828111610147576103b09036908701610178565b9390926103bb61014c565b9660c435918211610147576103d291369101610309565b989097608435966108ae565b3461014757604080600319360112610147576103f8610131565b60243567ffffffffffffffff811161014757610418903690600401610309565b60018360601b17918254917f898da98c106c91ce6f05405740b0ed23b5c4dc847a0dd1996fb93189d8310bef3d526020958692848452813d2082527f8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f6060527f301013e8a31863902646dc218ecd889c37491c2967a8104d5ff1cf42af0f9ea46080527fc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc660a0524660c0523060e05260a060602084526119013d526042601e203d52818101353d1a8452813760803d913d9060416fa2a8918ca85bafe22016d0b997e4df5f600160ff1b03606051109114165afa5082600051143d02156105565760019060001943014060e01c01018091556000527f997a42216df16c8b9e7caf2fc71c59dba956f1f2b12320f87a80a5879464217d826000a26000f35b638baa579f6000526004601cfd5b919082519283825260005b848110610590575050826000602080949584010152601f8019910116010190565b60208183018101518483018201520161056f565b34610147576000366003190112610147576105bd610281565b601581526020907426bab63a34b1b0b63632b92bb4ba3429b4b3b732b960591b828201526105e9610281565b610627600191828152603160f81b8582015261061960405194600f60f81b865260e08787015260e0860190610564565b908482036040860152610564565b92466060840152306080840152600060a084015282840360c08401528060605194858152019360809160005b8281106106605785870386f35b8351875295810195928101928401610653565b34610147576060806003193601126101475767ffffffffffffffff90600435828111610147576106a7903690600401610178565b6106b2939193610162565b91604435908111610147576106cb903690600401610309565b948260051b927fe75b4aefef1358e66ac7ed2f180022e0a7f661dcd2781630ce58e05bb8bdb1c13d526020809785848337858220825260806001988989821b175460409788918252823d2082527f8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f83527f301013e8a31863902646dc218ecd889c37491c2967a8104d5ff1cf42af0f9ea484527fc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc660a0524660c0523060e05260a0832086526119013d526042601e203d52818101353d1a865281373d9260416fa2a8918ca85bafe22016d0b997e4df5f600160ff1b033d9351109114165afa50600095858751143d021561083857858752865b85810361081a5750509083918787987fc45e3a0dd412bcad8d62398d74d66b1c8449f38beb10da275e4da0c6d3a811a49798525282370183a280f35b8089918501358060215283878b209160ff161b8154179055016107de565b638baa579f87526004601cfd5b346101475760003660031901126101475760013360601b176001815460001943014060e01c01018091553d52337f997a42216df16c8b9e7caf2fc71c59dba956f1f2b12320f87a80a5879464217d60203da260203df35b3d546001600160a01b03163d5260203df35b95919699989394929460609281148189141615610b2c573d5460a01c15610b1f5760051b977fc4d2f044d99707794280032fc14879a220a3f7dc766d75100809624f91d69e973d528651602080980120875260409989838c37898b208b52873d5b8b8103610b015750908a852085528a866080378a6080206080528c60a0528b6001978885881b175460c05260e03d2082527f8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f87527f301013e8a31863902646dc218ecd889c37491c2967a8104d5ff1cf42af0f9ea46080527fc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc660a0524660c0523060e05260a0872084526119013d526042601e203d52818101353d1a8452813760803d913d9060416fa2a8918ca85bafe22016d0b997e4df5f600160ff1b038951109114165afa5060009a818c51143d02828d52816021528b8d20908154888460ff161b91818316901517610af457179055878c528588528a52807fc45e3a0dd412bcad8d62398d74d66b1c8449f38beb10da275e4da0c6d3a811a4848da28815610aed57849392918b9182558a968a818d378b8b8101965b610a7b575b8a8a523060a01b84558b0183f35b9783808b839e969798999a9b845186019088019481869235938491018337603f19818d0181013591890101355af115610ae457838a918e958e523d90523d868883013e3d01603f01601f19169b0197878914610adc57969594939287610a68565b508392610a6d565b843d81803e3d90fd5b898b8a8952f35b638baa579f8f526004601cfd5b858101898201358a018035908190850183378120905201889061090f565b63ab143c063d526004601cfd5b633b800a463d526004601cfdfea264697066735822122076568aa35fd73a6145e7f8d1b3c8f45b289533e5e1509cb6bb468a6821351b2864736f6c63430008120033";

    bytes32 public constant MULTICALLER_WITH_SIGNER_INITCODEHASH =
        0x8959349c8789154069e125cfdd8c43b9eb4b8e79103ad33d180b530341979f87;

    bytes32 public constant MULTICALLER_WITH_SIGNER_CREATE2_SALT =
        0x0000000000000000000000000000000000000000cbfac55aed697200835a53f7;

    address public constant MULTICALLER_WITH_SIGNER_CREATE2_DEPLOYED_ADDRESS =
        0x000000000000a5183fcB3bb58a7Ce24ba2AddFDd;

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

        // vm.etch(LibMulticaller.MULTICALLER, address(new Multicaller()).code);
        // multicaller = Multicaller(payable(LibMulticaller.MULTICALLER));

        vm.etch(LibMulticaller.MULTICALLER_WITH_SIGNER, address(new MulticallerWithSigner()).code);
        vm.store(LibMulticaller.MULTICALLER_WITH_SIGNER, 0, bytes32(uint256(1 << 160)));
        multicallerWithSigner =
            MulticallerWithSigner(payable(LibMulticaller.MULTICALLER_WITH_SIGNER));

        _deployTargets();
    }

    function _deployTargets() internal virtual {
        targetA = new MulticallerTarget("A");
        targetB = new MulticallerTarget("B");
        fallbackTargetA = new FallbackTarget();
        fallbackTargetB = new FallbackTarget();
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
                    _multicallerWithSignerDomainSeparator(),
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

    function testMulticallerWithSignerRevertsWithNastyArrayLength() public {
        address target = address(multicallerWithSigner);
        bool anyFail;
        assembly {
            let m := mload(0x40)
            mstore(m, 0x17447cf1) // `noncesInvalidated(address,uint256[])`.
            mstore(add(m, 0x20), 1)
            mstore(add(m, 0x40), 0x40)
            mstore(add(m, 0x60), 1)
            mstore(add(m, 0x80), 0)
            if iszero(staticcall(gas(), target, add(m, 0x1c), 0x84, 0x00, 0x00)) { anyFail := 1 }
            mstore(add(m, 0x60), 2)
            if staticcall(gas(), target, add(m, 0x1c), 0x84, 0x00, 0x00) { anyFail := 1 }
            mstore(add(m, 0x60), 1)
            if iszero(staticcall(gas(), target, add(m, 0x1c), 0x84, 0x00, 0x00)) { anyFail := 1 }
        }
        assertEq(anyFail, false);
    }

    function _callMulticallerWithSigner(_TestTemps memory t, uint256 value)
        internal
        returns (bytes[] memory results)
    {
        results = multicallerWithSigner.aggregateWithSigner{value: value}(
            string(t.message), t.targets, t.data, t.values, t.nonce, t.signer, t.signature
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
                multicallerWithSigner.invalidateNoncesForSigner(nonces, signer, signature);
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
                multicallerWithSigner.incrementNonceSaltForSigner(signer, signature);

                vm.expectRevert(MulticallerWithSigner.InvalidSignature.selector);
                multicallerWithSigner.incrementNonceSaltForSigner(signer, signature);
            }
            uint256 nonceSaltAfter = multicallerWithSigner.nonceSaltOf(signer);
            assertEq(nextNonceSalt, nonceSaltAfter);
        }
    }

    function _generateInvalidateNoncesSignature(
        uint256[] memory nonces,
        address signer,
        uint256 privateKey
    ) internal returns (bytes memory signature) {
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                _multicallerWithSignerDomainSeparator(),
                keccak256(
                    abi.encode(
                        keccak256("InvalidateNoncesForSigner(uint256[] nonces,uint256 nonceSalt)"),
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
        returns (bytes memory signature)
    {
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                _multicallerWithSignerDomainSeparator(),
                keccak256(
                    abi.encode(
                        keccak256("IncrementNonceSaltForSigner(uint256 nonceSalt)"),
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

    function testOffsetTrick(uint256 a, uint256 b, uint256 c) public {
        unchecked {
            uint256 aDiff = a - c;
            uint256 bDiff = b - c;
            uint256 cPlus = c + 0x20;
            assertEq(cPlus + aDiff, a + 0x20);
            assertEq(cPlus + bDiff, b + 0x20);
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
