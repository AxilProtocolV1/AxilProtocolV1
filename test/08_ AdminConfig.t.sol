// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {AxilProtocolV1} from "../src/AxilProtocolV1.sol";

/**
 * @title Admin Configuration Tests
 * @author Axil Protocol Team
 * @notice Comprehensive test suite for admin configuration functions
 * @dev Tests all updateConfig paths and access control
 */
contract AdminConfigTest is Test {
    AxilProtocolV1 public axil;
    
    // Test addresses
    address public admin = address(0x1);
    address public signer = address(0x2);
    address public sweepReceiver = address(0x3);
    address public attacker = address(0x999);
    
    // Events to watch for
    event ConfigUpdated(uint8 indexed parameter, uint256 newValue, address newAddr);
    
    function setUp() public {
        vm.startPrank(admin);
        axil = new AxilProtocolV1(
            admin, 
            signer, 
            sweepReceiver, 
            address(0x4), 
            address(0x5), 
            keccak256("SALT")
        );
        vm.stopPrank();
    }
    
    /**
     * @notice Test 8.1: Update MaxClaim limit
     * @dev Verifies admin can increase claim limit
     */
    function test_UpdateMaxClaim() public {
        uint128 newLimit = 10 ether;
        
        vm.prank(admin);
        vm.expectEmit(true, true, true, true);
        emit ConfigUpdated(uint8(AxilProtocolV1.ConfigKey.MaxClaim), newLimit, address(0));
        axil.updateConfig(AxilProtocolV1.ConfigKey.MaxClaim, newLimit, address(0));
        
        ( , , , uint128 maxClaim, , , , , ) = axil.config();
        assertEq(maxClaim, newLimit, "MaxClaim should be updated");
    }
    
    /**
     * @notice Test 8.2: Update BatchIter limit
     * @dev Verifies admin can change batch processing iterations
     */
    function test_UpdateBatchIter() public {
        uint32 newBatchIter = 100;
        
        vm.prank(admin);
        vm.expectEmit(true, true, true, true);
        emit ConfigUpdated(uint8(AxilProtocolV1.ConfigKey.BatchIter), newBatchIter, address(0));
        axil.updateConfig(AxilProtocolV1.ConfigKey.BatchIter, newBatchIter, address(0));
        
        ( , , , , , uint32 batchIter, , , ) = axil.config();
        assertEq(batchIter, newBatchIter, "BatchIter should be updated");
    }
    
    /**
     * @notice Test 8.3: Update Signer address
     * @dev Verifies admin can change the signer address
     */
    function test_UpdateSigner() public {
        address newSigner = address(0x999);
        
        vm.prank(admin);
        vm.expectEmit(true, true, true, true);
        emit ConfigUpdated(uint8(AxilProtocolV1.ConfigKey.Signer), 0, newSigner);
        axil.updateConfig(AxilProtocolV1.ConfigKey.Signer, 0, newSigner);
        
        (address signerAddr, , , , , , , , ) = axil.config();
        assertEq(signerAddr, newSigner, "Signer address should be updated");
    }
    
    /**
     * @notice Test 8.4: Update SweepReceiver address
     * @dev Verifies admin can change the sweep receiver
     */
    function test_UpdateSweepReceiver() public {
        address newSweep = address(0x888);
        
        vm.prank(admin);
        vm.expectEmit(true, true, true, true);
        emit ConfigUpdated(uint8(AxilProtocolV1.ConfigKey.Sweep), 0, newSweep);
        axil.updateConfig(AxilProtocolV1.ConfigKey.Sweep, 0, newSweep);
        
        (, address sweepAddr, , , , , , , ) = axil.config();
        assertEq(sweepAddr, newSweep, "SweepReceiver should be updated");
    }
    
    /**
     * @notice Test 8.5: Update BurnQueueLimit
     * @dev Verifies admin can change the burn queue limit
     */
    function test_UpdateBurnLimit() public {
        uint128 newLimit = 20 ether;
        
        vm.prank(admin);
        vm.expectEmit(true, true, true, true);
        emit ConfigUpdated(uint8(AxilProtocolV1.ConfigKey.BurnLimit), newLimit, address(0));

axil.updateConfig(AxilProtocolV1.ConfigKey.BurnLimit, newLimit, address(0));
        
        ( , , , , uint128 maxBurn, , , , ) = axil.config();
        assertEq(maxBurn, newLimit, "BurnLimit should be updated");
    }
    
    /**
     * @notice Test 8.6: Update UseAllowlist flag
     * @dev Verifies admin can toggle merchant allowlist
     */
    function test_UpdateUseAllowlist() public {
        uint32 newValue = 1;
        
        vm.prank(admin);
        vm.expectEmit(true, true, true, true);
        emit ConfigUpdated(uint8(AxilProtocolV1.ConfigKey.UseAllowlist), newValue, address(0));
        axil.updateConfig(AxilProtocolV1.ConfigKey.UseAllowlist, newValue, address(0));
        
        ( , , , , , , uint32 useAllowlist, , ) = axil.config();
        assertEq(useAllowlist, newValue, "UseAllowlist should be updated");
    }
    
    /**
     * @notice Test 8.7: Update BurnCooldown
     * @dev Verifies admin can change burn cooldown period
     */
    function test_UpdateBurnCooldown() public {
        uint32 newCooldown = 120;
        
        vm.prank(admin);
        vm.expectEmit(true, true, true, true);
        emit ConfigUpdated(uint8(AxilProtocolV1.ConfigKey.BurnCooldown), newCooldown, address(0));
        axil.updateConfig(AxilProtocolV1.ConfigKey.BurnCooldown, newCooldown, address(0));
        
        ( , , , , , , , uint32 burnCooldown, ) = axil.config();
        assertEq(burnCooldown, newCooldown, "BurnCooldown should be updated");
    }
    
    /**
     * @notice Test 8.8: Update MinExecution amount
     * @dev Verifies admin can change minimum execution amount
     */
    function test_UpdateMinExecution() public {
        uint128 newMin = 0.01 ether;
        
        vm.prank(admin);
        vm.expectEmit(true, true, true, true);
        emit ConfigUpdated(uint8(AxilProtocolV1.ConfigKey.MinExecution), newMin, address(0));
        axil.updateConfig(AxilProtocolV1.ConfigKey.MinExecution, newMin, address(0));
        
        ( , , uint128 minAmount, , , , , , ) = axil.config();
        assertEq(minAmount, newMin, "MinExecution should be updated");
    }
    
    /**
     * @notice Test 8.9: Update MaxRetries
     * @dev Verifies admin can change maximum retry attempts
     */
    function test_UpdateMaxRetries() public {
        uint32 newRetries = 5;
        
        vm.prank(admin);
        vm.expectEmit(true, true, true, true);
        emit ConfigUpdated(uint8(AxilProtocolV1.ConfigKey.MaxRetries), newRetries, address(0));
        axil.updateConfig(AxilProtocolV1.ConfigKey.MaxRetries, newRetries, address(0));
        
        ( , , , , , , , , uint32 maxRetries) = axil.config();
        assertEq(maxRetries, newRetries, "MaxRetries should be updated");
    }
    
    /**
     * @notice Test 8.10: Only admin can update config
     * @dev Verifies non-admin cannot call updateConfig
     */
    function test_RevertWhen_NotAdmin() public {
        vm.prank(attacker);
        vm.expectRevert();
        axil.updateConfig(AxilProtocolV1.ConfigKey.MaxClaim, 10 ether, address(0));
    }
    
    /**
     * @notice Test 8.11: Cannot set zero address for signer
     * @dev Verifies zero address protection
     */
    function test_RevertWhen_ZeroAddressForSigner() public {
        vm.prank(admin);
        vm.expectRevert(AxilProtocolV1.Axil__ZeroAddressNotAllowed.selector);
        axil.updateConfig(AxilProtocolV1.ConfigKey.Signer, 0, address(0));
    }
    
    /**
     * @notice Test 8.12: Cannot set zero address for sweep
     * @dev Verifies zero address protection
     */
    function test_RevertWhen_ZeroAddressForSweep() public {
        vm.prank(admin);
        vm.expectRevert(AxilProtocolV1.Axil__ZeroAddressNotAllowed.selector);
        axil.updateConfig(AxilProtocolV1.ConfigKey.Sweep, 0, address(0));

}
    
    /**
     * @notice Test 8.13: Cannot exceed max batch size
     * @dev Verifies batch size limit
     */
    function test_RevertWhen_BatchIterTooHigh() public {
        uint256 tooHigh = 1000;
        
        vm.prank(admin);
        vm.expectRevert(AxilProtocolV1.Axil__BatchSizeExceeded.selector);
        axil.updateConfig(AxilProtocolV1.ConfigKey.BatchIter, tooHigh, address(0));
    }
}