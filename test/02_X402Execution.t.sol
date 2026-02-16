// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {AxilProtocolV1} from "../src/AxilProtocolV1.sol";


/**
 * @title X402 Execution Tests
 * @author Axil Protocol Team
 * @notice High-performance signature verification and execution testing
 */
contract X402ExecutionTest is Test {
    AxilProtocolV1 public axil;
    
    uint256 constant SIGNER_KEY = 0xA1;
    address public signer;
    address public agent = address(0x8);
    address public merchant = address(0x6);
    address public user = address(0x7);

    // FIXED: Typehash matches the actual function name in the contract
    bytes32 public constant EXECUTE_TYPEHASH = keccak256(
        "Execute(address merchant,address user,bytes32 packedIntent,uint128 amount,uint256 deadline,uint128 salt,address agent)"
    );

    /**
     * @notice Initialize test environment and deploy protocol
     */
    function setUp() public {
        signer = vm.addr(SIGNER_KEY);
        vm.startPrank(address(0x1));
        axil = new AxilProtocolV1(address(0x1), signer, address(0x3), address(0x4), address(0x5), keccak256("SALT"));
        vm.stopPrank();
        vm.deal(agent, 10 ether);
    }

    /**
     * @notice Test 2.1: Successful X402 intent execution with EIP-712 signature
     */
    function test_ExecuteX402_Success() public {
        uint128 amount = 1 ether;
        uint256 deadline = block.timestamp + 1000;
        uint128 salt = 12345;
        bytes32 packedIntent = axil.packIntent(1, 1);

        // Generate EIP-712 struct hash with perfectly aligned uint128 types
        bytes32 structHash = keccak256(abi.encode(
            EXECUTE_TYPEHASH, 
            merchant, 
            user, 
            packedIntent, 
            amount, 
            deadline, 
            salt, 
            agent
        ));

        // Calculate domain separator matching the contract's EIP712 implementation
        bytes32 domainSeparator = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes("AxilProtocolV1")),
            keccak256(bytes("1")),
            block.chainid,
            address(axil)
        ));

        // Sign the final digest
        bytes32 finalHash = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, finalHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Execute as agent and verify intent settlement
        vm.prank(agent);
        // FIXED: Changed from executeX402 to execute (correct function name)
        axil.execute{value: amount}(merchant, user, packedIntent, deadline, salt, signature);
        
        assertTrue(axil.isIntentExecuted(packedIntent));
        
        uint256 expectedMerchantShare = amount - ((amount * 100) / 10000); // Verify 1% fee deduction
        assertEq(address(merchant).balance, expectedMerchantShare);
    }
}