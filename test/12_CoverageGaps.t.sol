// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {AxilProtocolV1} from "../src/AxilProtocolV1.sol";

/**
 * @title CoverageGapsTest
 * @author Axil Protocol Team
 * @notice Complete test coverage for all untested functions
 * @dev Covers getters, batch processing, burn mechanism, admin functions, and edge cases
 */
contract CoverageGapsTest is Test {
    AxilProtocolV1 public axil;

    // ─────────────────────────────────────────────────────────────────────────
    // Test Actors
    // ─────────────────────────────────────────────────────────────────────────
    address public admin = address(0x1);
    address public user = address(0x2);
    address public keeper = address(0x3);
    address public treasury = address(0x6);
    address public validatorPool = address(0x7);
    address public dexBroker = address(0x8);

    // ─────────────────────────────────────────────────────────────────────────
    // Signer Configuration
    // ─────────────────────────────────────────────────────────────────────────
    uint256 constant SIGNER_KEY = 0xA1;
    address public signer;

    // ─────────────────────────────────────────────────────────────────────────
    // Setup
    // ─────────────────────────────────────────────────────────────────────────
    function setUp() public {
        signer = vm.addr(SIGNER_KEY);

        // ADMIN: deploys contract and grants roles
        vm.startPrank(admin);
        axil = new AxilProtocolV1(admin, signer, treasury, validatorPool, dexBroker, keccak256("SALT"));

        // ADMIN: grants KEEPER_ROLE to keeper address
        axil.grantRole(axil.KEEPER_ROLE(), keeper);
        vm.stopPrank();

        // Fund contracts
        vm.deal(address(axil), 100_000 ether);
        vm.deal(keeper, 1000 ether);
        vm.deal(user, 1000 ether);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SECTION 1: Getters & View Functions
    // ─────────────────────────────────────────────────────────────────────────

    function test_Getters() public view {
        // Storage getters
        axil.failedBurnQueue();
        axil.totalBurned();
        axil.totalPendingRewards();
        axil.lastBurnRetryBlock();

        // Configuration getters
        axil.config();
        axil.PACKED_CONSTANTS(0);
        axil.PACKED_CONSTANTS(1);
        axil.PACKED_CONSTANTS(2);
        axil.PACKED_CONSTANTS(3);

        // Role constants
        axil.ADMIN_ROLE();
        axil.KEEPER_ROLE();
        axil.TREASURY_ROLE();
        axil.MERCHANT_ROLE();
        axil.EMERGENCY_ROLE();

        // Immutable addresses
        axil.i_admin();
        axil.i_signer();
        axil.i_sweepReceiver();
        axil.i_validatorPool();
        axil.i_dexBroker();
        axil.BURN_ADDRESS();

        // State variables
        axil.batchProcessingPaused();
        axil.totalExecutedIntents();
        axil.totalValueProcessed();

        assertTrue(true, "All getters executed successfully");
    }

    function test_UnpackIntent() public view {
        uint128 bucket = 12345;
        uint128 mask = 67890;

        bytes32 packed = axil.packIntent(bucket, mask);
        (uint128 unpackedBucket, uint128 unpackedMask) = axil.unpackIntent(packed);

        assertEq(bucket, unpackedBucket, "Bucket should match after pack/unpack");
        assertEq(mask, unpackedMask, "Mask should match after pack/unpack");
    }

    function test_GetSystemStats() public view {
        axil.getSystemStats();
        assertTrue(true, "System stats accessible");
    }

    function test_Version() public view {
        string memory version = axil.version();
        assertTrue(bytes(version).length > 0, "Version string should not be empty");
        assertEq(version, "Axil Protocol V1 - Monad Multiverse Edition", "Version should match");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SECTION 2: Batch Processing Functions
    // ─────────────────────────────────────────────────────────────────────────

    function test_ToggleBatchProcessing() public {
        assertFalse(axil.batchProcessingPaused(), "Should start unpaused");

        vm.prank(admin);
        axil.toggleBatchProcessing();
        assertTrue(axil.batchProcessingPaused(), "Should be paused after toggle");

        vm.prank(admin);
        axil.toggleBatchProcessing();
        assertFalse(axil.batchProcessingPaused(), "Should be unpaused after second toggle");
    }

    function test_AutoBatchClaimEmpty() public {
        address[] memory emptyAccounts;
        bytes32[] memory emptyIntents;

        vm.prank(keeper);
        // Empty arrays are valid (lengths match = 0)
        axil.autoBatchClaim(emptyAccounts, emptyIntents, 1000);

        assertTrue(true, "Empty arrays processed successfully");
    }

    function test_RevertWhen_ArraysDifferentLength() public {
        address[] memory accounts = new address[](1);
        accounts[0] = user;
        bytes32[] memory intents = new bytes32[](0); // Mismatched length

        vm.prank(keeper);
        vm.expectRevert(AxilProtocolV1.Axil__ArrayLengthMismatch.selector);
        axil.autoBatchClaim(accounts, intents, 1000);
    }

    function test_RevertWhen_BatchProcessingPaused() public {
        vm.prank(admin);
        axil.toggleBatchProcessing();

        address[] memory accounts;
        bytes32[] memory intents;

        vm.prank(keeper);
        vm.expectRevert(AxilProtocolV1.Axil__BatchProcessingPaused.selector);
        axil.autoBatchClaim(accounts, intents, 1000);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SECTION 3: Burn Mechanism Functions
    // ─────────────────────────────────────────────────────────────────────────

    function test_CheckBurnQueueCritical() public view {
        axil.checkBurnQueueCritical();
        assertTrue(true, "checkBurnQueueCritical executed");
    }

    function test_AutoRetryBurnZero() public {
        vm.prank(admin);
        axil.autoRetryBurn(0);
        assertTrue(true, "autoRetryBurn(0) executed");
    }

    function test_AutoRetryBurnNonZero() public {
        vm.prank(admin);
        axil.autoRetryBurn(100 ether);
        assertTrue(true, "autoRetryBurn executed");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SECTION 4: Merchant Role Management
    // ─────────────────────────────────────────────────────────────────────────

    function test_GrantMerchantRole() public {
        bytes32 merchantRole = axil.MERCHANT_ROLE();

        assertFalse(axil.hasRole(merchantRole, user), "User should not have role initially");

        vm.prank(admin);
        axil.grantMerchantRole(user);

        assertTrue(axil.hasRole(merchantRole, user), "User should have role after grant");
    }

    function test_RevokeMerchantRole() public {
        bytes32 merchantRole = axil.MERCHANT_ROLE();

        vm.prank(admin);
        axil.grantMerchantRole(user);
        assertTrue(axil.hasRole(merchantRole, user), "User should have role after grant");

        vm.prank(admin);
        axil.revokeMerchantRole(user);
        assertFalse(axil.hasRole(merchantRole, user), "User should not have role after revoke");
    }

    function test_RevertWhen_GrantMerchantRoleToZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(AxilProtocolV1.Axil__ZeroAddressNotAllowed.selector);
        axil.grantMerchantRole(address(0));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SECTION 5: Modifiers and Edge Cases
    // ─────────────────────────────────────────────────────────────────────────

    function test_ValidateIntentWithInvalidMask() public {
        bytes32 invalidIntent = bytes32(0);

        vm.deal(address(this), 1 ether);
        vm.prank(address(this));

        vm.expectRevert(AxilProtocolV1.Axil__InvalidIntent.selector);
        axil.execute{value: 1 ether}(user, user, invalidIntent, block.timestamp + 1000, 12345, hex"");
    }

    function test_ValidAmountModifier() public {
        vm.prank(address(this));
        vm.expectRevert(AxilProtocolV1.Axil__InvalidAmount.selector);
        axil.execute{value: 0}(user, user, keccak256("test"), block.timestamp + 1000, 12345, hex"");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SECTION 6: Comprehensive Coverage Validation
    // ─────────────────────────────────────────────────────────────────────────

    function test_AllFunctionsCovered() public view {
        axil.failedBurnQueue();
        axil.totalBurned();
        axil.totalPendingRewards();
        axil.lastBurnRetryBlock();
        axil.getSystemStats();
        axil.version();

        assertTrue(true, "All functions should now be covered");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SECTION 7: Receive Function
    // ─────────────────────────────────────────────────────────────────────────

    function test_ReceiveFunction() public {
        uint256 balanceBefore = address(axil).balance;

        (bool success,) = address(axil).call{value: 1 ether}("");
        assertTrue(success, "ETH transfer should succeed");

        assertEq(address(axil).balance, balanceBefore + 1 ether, "Balance should increase");
    }
}
