// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {AxilProtocolV1} from "../src/AxilProtocolV1.sol";


/**
 * @title Ultra-Deep Fuzzing Suite
 * @author Axil Protocol Team
 * @notice Stress testing with 1M iterations to ensure uint128 arithmetic integrity
 */
contract FuzzTest is Test {
    AxilProtocolV1 public axil;
    
    uint256 constant SIGNER_KEY = 0xA1;
    address public signer;
    address public merchant = address(0x6);
    address public user = address(0x7);
    address public agent = address(0x8);


    bytes32 public constant EXECUTE_TYPEHASH = keccak256(
        "Execute(address merchant,address user,bytes32 packedIntent,uint128 amount,uint256 deadline,uint128 salt,address agent)"
    );


    function setUp() public {
        signer = vm.addr(SIGNER_KEY);
        vm.prank(address(0x1));
        axil = new AxilProtocolV1(address(0x1), signer, address(0x3), address(0x4), address(0x5), keccak256("SALT"));
        // INFINITE BALANCE: Deal max possible ETH to agent for 1M runs
        vm.deal(agent, type(uint256).max); 
    }


    /**
     * @notice Heavy Fuzzing: Executes X402 with massive variety of amounts and salts
     */
    function testFuzz_ExecuteX402_Extreme(uint128 amount, uint128 salt) public {
        // We bound amount to avoid dust (below 0.001) and insane values above balance
        amount = uint128(bound(amount, 0.001 ether, 1000000 ether));
        uint256 deadline = block.timestamp + 1000;
        
        // Ensure packedIntent is always unique using the fuzzing salt
        bytes32 packedIntent = keccak256(abi.encodePacked(salt, "FUZZ"));


        bytes32 structHash = keccak256(abi.encode(EXECUTE_TYPEHASH, merchant, user, packedIntent, amount, deadline, salt, agent));
        bytes32 finalHash = keccak256(abi.encodePacked("\x19\x01", _getDomainSeparator(), structHash));
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, finalHash);
        bytes memory signature = abi.encodePacked(r, s, v);


        vm.prank(agent);
        axil.execute{value: amount}(merchant, user, packedIntent, deadline, salt, signature);


        assertTrue(axil.isIntentExecuted(packedIntent));
    }


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