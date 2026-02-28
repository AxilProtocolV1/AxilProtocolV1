// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {AxilProtocolV1} from "../src/AxilProtocolV1.sol";

/**
 * @title Transfer and Sweep Tests
 * @author Axil Protocol Team
 * @notice Tests for admin transfer functions and emergency sweep
 * @dev Validates role migration and fund recovery mechanisms
 */
contract TransferAndSweepTest is Test {
    AxilProtocolV1 public axil;

    // Test addresses
    address public admin = address(0x1);
    address public newAdmin = address(0x2);
    address public emergency = address(0x3);
    address public newEmergency = address(0x4);
    address public attacker = address(0x999);

    // Events
    event AdminTransferred(address indexed oldAdmin, address indexed newAdmin);
    event EmergencyTransferred(address indexed oldEmergency, address indexed newEmergency);
    event EmergencySweep(uint256 amount, address indexed receiver);

    function setUp() public {
        vm.startPrank(admin);
        axil = new AxilProtocolV1(
            admin,
            address(0x5), // signer
            address(0x6), // sweepReceiver
            address(0x7), // validatorPool
            address(0x8), // dexBroker
            keccak256("SALT")
        );

        axil.grantRole(axil.EMERGENCY_ROLE(), emergency);
        axil.grantRole(axil.TREASURY_ROLE(), admin);
        vm.stopPrank();

        // Fund contract with 10 MON for sweep tests
        vm.deal(address(axil), 10 ether);
    }

    /**
     * @notice Test 9.1: Admin transfers role to new address
     * @dev Verifies successful admin role migration
     */
    function test_TransferAdmin() public {
        vm.prank(admin);
        vm.expectEmit(true, true, false, false);
        emit AdminTransferred(admin, newAdmin);
        axil.transferAdmin(newAdmin);

        assertFalse(axil.hasRole(axil.ADMIN_ROLE(), admin), "Old admin should lose ADMIN_ROLE");
        assertTrue(axil.hasRole(axil.ADMIN_ROLE(), newAdmin), "New admin should gain ADMIN_ROLE");
    }

    /**
     * @notice Test 9.2: Cannot transfer admin to zero address
     */
    function test_RevertWhen_TransferAdminToZero() public {
        vm.prank(admin);
        vm.expectRevert(AxilProtocolV1.Axil__ZeroAddressNotAllowed.selector);
        axil.transferAdmin(address(0));
    }

    /**
     * @notice Test 9.3: Non-admin cannot transfer admin
     */
    function test_RevertWhen_NonAdminTransfers() public {
        vm.prank(attacker);
        vm.expectRevert();
        axil.transferAdmin(newAdmin);
    }

    /**
     * @notice Test 9.4: Emergency role transfers
     */
    function test_TransferEmergency() public {
        vm.prank(emergency);
        vm.expectEmit(true, true, false, false);
        emit EmergencyTransferred(emergency, newEmergency);
        axil.transferEmergency(newEmergency);

        assertFalse(axil.hasRole(axil.EMERGENCY_ROLE(), emergency), "Old emergency should lose role");
        assertTrue(axil.hasRole(axil.EMERGENCY_ROLE(), newEmergency), "New emergency should gain role");
    }

    /**
     * @notice Test 9.5: Cannot transfer emergency to zero
     */
    function test_RevertWhen_TransferEmergencyToZero() public {
        vm.prank(emergency);
        vm.expectRevert(AxilProtocolV1.Axil__ZeroAddressNotAllowed.selector);
        axil.transferEmergency(address(0));
    }

    /**
     * @notice Test 9.6: Non-emergency cannot transfer emergency
     */
    function test_RevertWhen_NonEmergencyTransfers() public {
        vm.prank(attacker);
        vm.expectRevert();
        axil.transferEmergency(newEmergency);
    }

    /**
     * @notice Test 9.7: Treasury sweeps excess funds
     */
    function test_Sweep() public {
        (, address sweepAddr,,,,,,,) = axil.config();
        uint256 initialBalance = address(axil).balance;
        uint256 sweepAmount = 5 ether;

        vm.prank(admin);
        vm.expectEmit(true, true, false, false);
        emit EmergencySweep(sweepAmount, sweepAddr);
        axil.sweep(sweepAmount);

        assertLt(address(axil).balance, initialBalance, "Balance should decrease");
    }

    /**
     * @notice Test 9.8: Sweep with amount = 0 sweeps all available
     * @dev Verifies sweep(0) behavior
     */
    function test_SweepZero() public {
        uint256 initialBalance = address(axil).balance;
        (,, uint256 available) = axil.getContractBalance();

        vm.prank(admin);
        axil.sweep(0);

        assertEq(address(axil).balance, initialBalance - available, "Should sweep all available");
    }

    /**
     * @notice Test 9.9: Non-treasury cannot sweep
     */
    function test_RevertWhen_NonTreasurySweeps() public {
        vm.prank(attacker);
        vm.expectRevert();
        axil.sweep(1 ether);
    }

    /**
     * @notice Test 9.10: Emergency pause
     */
    function test_EmergencyPause() public {
        vm.prank(emergency);
        axil.emergencyPause();
        assertTrue(axil.paused(), "Should be paused");
    }

    /**
     * @notice Test 9.11: Emergency unpause
     */
    function test_EmergencyUnpause() public {
        vm.prank(emergency);
        axil.emergencyPause();
        assertTrue(axil.paused(), "Should be paused");

        vm.prank(emergency);
        axil.emergencyUnpause();
        assertFalse(axil.paused(), "Should be unpaused");
    }

    /**
     * @notice Test 9.12: Non-emergency cannot pause
     */
    function test_RevertWhen_NonEmergencyPauses() public {
        vm.prank(attacker);
        vm.expectRevert();
        axil.emergencyPause();
    }

    /**
     * @notice Test 9.13: Admin pause/unpause
     */
    function test_AdminPause() public {
        vm.prank(admin);
        axil.pause();
        assertTrue(axil.paused(), "Should be paused");

        vm.prank(admin);
        axil.unpause();
        assertFalse(axil.paused(), "Should be unpaused");
    }

    /**
     * @notice Test 9.14: Non-admin cannot pause
     */
    function test_RevertWhen_NonAdminPauses() public {
        vm.prank(attacker);
        vm.expectRevert();
        axil.pause();
    }

    /**
     * @notice Test 9.15: Complete role lifecycle
     */
    function test_RoleLifecycle() public {
        assertTrue(axil.hasRole(axil.ADMIN_ROLE(), admin), "Initial admin");
        assertTrue(axil.hasRole(axil.EMERGENCY_ROLE(), emergency), "Initial emergency");

        vm.prank(admin);
        axil.transferAdmin(newAdmin);

        vm.prank(emergency);
        axil.transferEmergency(newEmergency);

        assertTrue(axil.hasRole(axil.ADMIN_ROLE(), newAdmin), "New admin");
        assertTrue(axil.hasRole(axil.EMERGENCY_ROLE(), newEmergency), "New emergency");
        assertFalse(axil.hasRole(axil.ADMIN_ROLE(), admin), "Old admin gone");
        assertFalse(axil.hasRole(axil.EMERGENCY_ROLE(), emergency), "Old emergency gone");
    }
}
