// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {AxilProtocolV1} from "../src/AxilProtocolV1.sol";


/**
 * @title Initialization Tests
 * @author Axil Protocol Team
 * @notice Test suite for contract initialization and configuration
 */
contract InitializationTest is Test {
    AxilProtocolV1 public axil;
    
    address public admin = address(0x1);
    address public signer = address(0x2);
    address public sweepReceiver = address(0x3);
    address public validatorPool = address(0x4);
    address public dexBroker = address(0x5);
    bytes32 public salt = keccak256("AXIL_TEST");
    
    /**
     * @notice Test 1.1: Verifies successful deployment and role assignment
     */
    function test_Deployment_Success() public {
        axil = new AxilProtocolV1(admin, signer, sweepReceiver, validatorPool, dexBroker, salt);
        assertEq(axil.hasRole(axil.ADMIN_ROLE(), admin), true);
        assertEq(axil.hasRole(axil.DEFAULT_ADMIN_ROLE(), admin), true);
        assertEq(axil.i_admin(), admin);
        assertEq(axil.i_signer(), signer);
        assertEq(axil.i_sweepReceiver(), sweepReceiver);
        assertEq(axil.i_validatorPool(), validatorPool);
        assertEq(axil.i_dexBroker(), dexBroker);
    }
    
    /**
     * @notice Test 1.2: Verifies zero address validation in constructor
     */
    function test_Deployment_RevertWhen_ZeroAddress() public {
        vm.expectRevert(AxilProtocolV1.Axil__ZeroAddressNotAllowed.selector);
        new AxilProtocolV1(address(0), signer, sweepReceiver, validatorPool, dexBroker, salt);
        vm.expectRevert(AxilProtocolV1.Axil__ZeroAddressNotAllowed.selector);
        new AxilProtocolV1(admin, address(0), sweepReceiver, validatorPool, dexBroker, salt);
        vm.expectRevert(AxilProtocolV1.Axil__ZeroAddressNotAllowed.selector);
        new AxilProtocolV1(admin, signer, address(0), validatorPool, dexBroker, salt);
    }
    
    /**
     * @notice Test 1.3: Verifies default system configuration values
     */
    function test_Config_InitialValues() public {
        axil = new AxilProtocolV1(admin, signer, sweepReceiver, validatorPool, dexBroker, salt);
        
        // Fixed: Unpack all 9 values from SystemConfig struct
        (
            address signerAddr,
            address sweepAddr,
            uint128 minAmount,
            uint128 maxClaim,
            uint128 maxBurn,
            uint32 batchIter,
            uint32 useAllowlist,
            uint32 burnCooldown,
            uint32 maxRetries
        ) = axil.config();
        
        // Check address fields
        assertEq(signerAddr, signer);
        assertEq(sweepAddr, sweepReceiver);
        
        // Check numeric values
        assertEq(minAmount, 0.001 ether);
        assertEq(maxClaim, 5 ether);
        assertEq(maxBurn, 10 ether);
        assertEq(batchIter, 50);
        assertEq(useAllowlist, 0);
        assertEq(burnCooldown, 60);
        assertEq(maxRetries, 3);
    }
}