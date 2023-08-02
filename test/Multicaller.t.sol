// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "./utils/TestPlus.sol";
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
        hex"6080806040523060a01b3d55610abb90816100188239f3fe6040608081526004361015610020575b50361561001b57600080fd5b6107a0565b6000803560e01c91826317447cf1146100aa57505080632eb48a80146100a55780633aeb2206146100a05780634eb311501461009b57806356b1a87f1461009657806384b0196e1461009157806387ec11ca1461008c5763f0c60f1a14610087573861000f565b61074a565b61054a565b6104f5565b610334565b61028f565b61023e565b6101a3565b346101275780600319360112610127576100c261012b565b9060243567ffffffffffffffff8111610123576100e3903690600401610172565b909284528060051b92845b848103610102575050602084526020520190f35b80602091830135808352603f8820549060ff161c60011681860152016100ee565b8380fd5b5080fd5b600435906001600160a01b038216820361014157565b600080fd5b60a435906001600160a01b038216820361014157565b602435906001600160a01b038216820361014157565b9181601f840112156101415782359167ffffffffffffffff8311610141576020808501948460051b01011161014157565b34610141576020806003193601126101415760043567ffffffffffffffff8111610141576101d5903690600401610172565b6000913383528160051b91835b83810361021f5750848495849552526040377fc45e3a0dd412bcad8d62398d74d66b1c8449f38beb10da275e4da0c6d3a811a4339160400183a280f35b8086918401358083526001603f88209160ff161b8154179055016101e2565b346101415760203660031901126101415761025761012b565b3001543d5260203df35b9181601f840112156101415782359167ffffffffffffffff8311610141576020838186019501011161014157565b60e03660031901126101415767ffffffffffffffff60048035828111610141576102bc9036908301610261565b9190602435848111610141576102d59036908401610172565b9094604435818111610141576102ee9036908601610172565b90606435838111610141576103069036908801610172565b949093610311610146565b9760c4359182116101415761032891369101610261565b999098608435976107b2565b346101415760403660031901126101415761034d61012b565b60243567ffffffffffffffff81116101415761036d903690600401610261565b9190308201908154907f898da98c106c91ce6f05405740b0ed23b5c4dc847a0dd1996fb93189d8310bef3d5260209482865260403d206040527f8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f6060527f301013e8a31863902646dc218ecd889c37491c2967a8104d5ff1cf42af0f9ea46080527fc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc660a0524660c0523060e05260a060602086526119013d52856042601e2091600093604182146104d2575b8415610494575b50505050156104865760019060001943014060e01c01018091556000527f997a42216df16c8b9e7caf2fc71c59dba956f1f2b12320f87a80a5879464217d826000a26000f35b638baa579f6000526004601cfd5b6000929394509080606492630b135d3f60e11b9687865260045260406024528160445283370181875afa90853d149060005114161638858180610440565b93600160808492863d52848860403781513d1a8452825afa5187143d0293610439565b3461014157600036600319011261014157600f3d5360e060205275154d756c746963616c6c6572576974685369676e657260f55261012060405261013161012152466060523060805261016060c0526101803df35b346101415760603660031901126101415767ffffffffffffffff6004358181116101415761057c903690600401610172565b61058792919261015c565b91604435908111610141576105a0903690600401610261565b90938260051b927fe75b4aefef1358e66ac7ed2f180022e0a7f661dcd2781630ce58e05bb8bdb1c13d526020958483883784872087523086015493604094855260603d2085527f8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f6060527f301013e8a31863902646dc218ecd889c37491c2967a8104d5ff1cf42af0f9ea46080527fc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc660a0524660c0523060e05260a060602088526119013d52876042601e209160009360418214610728575b84156106eb575b5050505015610486578460005260005b8481036106cb5750908391867fc45e3a0dd412bcad8d62398d74d66b1c8449f38beb10da275e4da0c6d3a811a49697600052528237016000a2005b8087918401358083526001603f6000209160ff161b815417905501610690565b6000929394509080606492630b135d3f60e11b96878652600452896024528160445283370181895afa90873d149060005114161638878180610680565b93600160808492863d5284888c3781513d1a8452825afa5189143d0293610679565b346101415760008060031936011261079d576020903033016001815460001943014060e01c01018091558152337f997a42216df16c8b9e7caf2fc71c59dba956f1f2b12320f87a80a5879464217d8383a2f35b80fd5b3d546001600160a01b03163d5260203df35b97919099959498939692986060938114818b141615610a78573d5460a01c15610a6b5760059b9a9b1b997fc4d2f044d99707794280032fc14879a220a3f7dc766d75100809624f91d69e973d528b60209c8d9a8b378920895260409b8c918c8484378c832083523d5b8d8103610a4857508c862086526080988d898b378d8a208a528560a0523088015460c05260e03d2084527f8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f87527f301013e8a31863902646dc218ecd889c37491c2967a8104d5ff1cf42af0f9ea48a527fc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc660a0524660c0523060e05260a0872083526119013d526042601e209360009a60418414610a26575b508a156109e6575b505050505083600052818852603f938460002092835493600198898360ff161b90868216901517610486578e9517905589600052878a528352807fc45e3a0dd412bcad8d62398d74d66b1c8449f38beb10da275e4da0c6d3a811a4856000a28a156109de578695949392506000558a968a818d378b8b8101965b61096b575b8b8b8b523060a01b600055016000f35b976000808b839e969798999a9b845186019088019481869235938491018337603f19818d0181013591890101355af1156109d457838a918e958e523d90523d60008783013e3d018601601f19169b01978789146109cd57969594939287610956565b508261095b565b3d6000803e3d6000fd5b828b8a526000f35b60009394959a50918091606493630b135d3f60e11b978887526004526024528160445283370181875afa90883d149060005114161694388881808e6108dc565b600190829c858588958a3d523781513d1a8452825afa5188143d0299386108d4565b9092508581018a8201358b0180359081908501833781209052018c918a9161081b565b63ab143c063d526004601cfd5b633b800a463d526004601cfdfea2646970667358221220df065481586e05c7c3518fad15b937e606ace5837d907434182eff1b7731690764736f6c63430008120033";

    bytes32 public constant MULTICALLER_WITH_SIGNER_INITCODEHASH =
        0x07da29be562a291a6ccd5765eac970beb654a7fa41201149c78acd5f22a3015d;

    bytes32 public constant MULTICALLER_WITH_SIGNER_CREATE2_SALT =
        0x00000000000000000000000000000000000000008c6c52f2e388bb008fe279ec;

    address public constant MULTICALLER_WITH_SIGNER_CREATE2_DEPLOYED_ADDRESS =
        0x0000000000003C6E14B7f65dA82b10132d9904F9;

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

        // vm.etch(LibMulticaller.MULTICALLER_WITH_SIGNER, address(new MulticallerWithSigner()).code);
        // vm.store(LibMulticaller.MULTICALLER_WITH_SIGNER, 0, bytes32(uint256(1 << 160)));
        // multicallerWithSigner =
        //     MulticallerWithSigner(payable(LibMulticaller.MULTICALLER_WITH_SIGNER));

        _deployTargets();
    }

    function _deployTargets() internal virtual {
        targetA = new MulticallerTarget("A");
        targetB = new MulticallerTarget("B");
        fallbackTargetA = new FallbackTarget();
        fallbackTargetB = new FallbackTarget();
    }

    function _deployERC1271Contracts() internal virtual {
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
            multicallerWithSigner.invalidateNoncesForSigner(nonces, erc1271Malicious, signature);

            vm.expectEmit(true, true, true, true);
            emit NoncesInvalidated(erc1271Wallet, nonces);
            multicallerWithSigner.invalidateNoncesForSigner(nonces, erc1271Wallet, signature);

            vm.expectRevert(MulticallerWithSigner.InvalidSignature.selector);
            multicallerWithSigner.invalidateNoncesForSigner(nonces, erc1271Malicious, signature);
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

    function testMultiCallerWithSignerIncrementNonceSaltWithERC1271(uint256) public {
        _deployERC1271Contracts();
        uint256 nonceSaltBefore = multicallerWithSigner.nonceSaltOf(erc1271Wallet);
        uint256 nextNonceSalt = _nextNonceSalt(nonceSaltBefore);
        bytes memory signature =
            _generateIncrementNonceSaltSignature(erc1271Wallet, erc721SignerPrivateKey);

        vm.expectRevert(MulticallerWithSigner.InvalidSignature.selector);
        multicallerWithSigner.incrementNonceSaltForSigner(erc1271Malicious, signature);

        emit NonceSaltIncremented(erc1271Wallet, nextNonceSalt);
        multicallerWithSigner.incrementNonceSaltForSigner(erc1271Wallet, signature);

        vm.expectRevert(MulticallerWithSigner.InvalidSignature.selector);
        multicallerWithSigner.incrementNonceSaltForSigner(erc1271Wallet, signature);
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

    function revertsOnNastyCalldata(address[] calldata a) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(a));
    }

    function testNastyCalldataRevert() public {
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

            // Check reverts if address has dirty upper bits.
            mstore(add(m, 0x60), not(0))
            if call(gas(), address(), 0, add(m, 0x1c), 0x80, 0x00, 0x00) { revert(0x00, 0x00) }
            mstore(add(m, 0x60), 0x112233)

            // Check reverts if length of array is excessive.
            mstore(add(m, 0x40), 2)
            if call(gas(), address(), 0, add(m, 0x1c), 0x80, 0x00, 0x00) { revert(0x00, 0x00) }

            // Check reverts if length of array is excessive.
            mstore(add(m, 0x40), shl(255, 1))
            if call(gas(), address(), 0, add(m, 0x1c), 0x80, 0x00, 0x00) { revert(0x00, 0x00) }
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
