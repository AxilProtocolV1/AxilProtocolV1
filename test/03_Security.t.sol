// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {AxilProtocolV1} from "../src/AxilProtocolV1.sol";


/**
 * @title Security Tests
 * @author Axil Protocol Team
 * @notice Validates replay protection and signature data integrity
 */
contract SecurityTest is Test {
    AxilProtocolV1 public axil;
    
    uint256 constant SIGNER_KEY = 0xA1;
    address public signer;
    address public agent = address(0x8);
    address public merchant = address(0x6);
    address public user = address(0x7);

    // FIXED: Updated typehash to match the contract's EXECUTE_TYPEHASH
    bytes32 public constant EXECUTE_TYPEHASH = keccak256(
        "Execute(address merchant,address user,bytes32 packedIntent,uint128 amount,uint256 deadline,uint128 salt,address agent)"
    );

    function setUp() public {
        signer = vm.addr(SIGNER_KEY);
        vm.prank(address(0x1));
        axil = new AxilProtocolV1(address(0x1), signer, address(0x3), address(0x4), address(0x5), keccak256("SALT"));
        vm.deal(agent, 10 ether);
    }

    /**
     * @notice Test 3.1: Reverts if execution data (amount) differs from the signed intent
     */
    function test_RevertIf_DataIsTampered() public {
        uint128 realAmount = 1 ether;
        uint128 fakeAmount = 10 ether;
        uint256 deadline = block.timestamp + 1000;
        uint128 salt = 555;
        bytes32 packedIntent = axil.packIntent(1, 1);

        bytes32 structHash = keccak256(abi.encode(EXECUTE_TYPEHASH, merchant, user, packedIntent, realAmount, deadline, salt, agent));
        bytes32 finalHash = keccak256(abi.encodePacked("\x19\x01", _getDomainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, finalHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(AxilProtocolV1.Axil__InvalidSignature.selector);
        vm.prank(agent);
        axil.execute{value: fakeAmount}(merchant, user, packedIntent, deadline, salt, signature);
    }

    /**
     * @notice Test 3.2: Prevents signature reuse (Replay Attack) using bit-mapped intent tracking
     */
    function test_RevertIf_SignatureReused() public {
        uint128 amount = 1 ether;
        uint256 deadline = block.timestamp + 1000;
        uint128 salt = 777;
        bytes32 packedIntent = axil.packIntent(1, 1);

        bytes32 structHash = keccak256(abi.encode(EXECUTE_TYPEHASH, merchant, user, packedIntent, amount, deadline, salt, agent));
        bytes32 finalHash = keccak256(abi.encodePacked("\x19\x01", _getDomainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, finalHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(agent);
        axil.execute{value: amount}(merchant, user, packedIntent, deadline, salt, signature);

        vm.expectRevert(AxilProtocolV1.Axil__IntentAlreadyExecuted.selector);
        vm.prank(agent);
        axil.execute{value: amount}(merchant, user, packedIntent, deadline, salt, signature);
    }

    /**
     * @dev Internal helper to generate EIP-712 domain separator
     */
    function _getDomainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes("AxilProtocolV1")),
            keccak256(bytes("1")),
            block.chainid,
            address(axil)
        ));
    }
}