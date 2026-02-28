// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {AxilProtocolV1} from "../src/AxilProtocolV1.sol";

/**
 * @title ClaimRewardsTest
 * @author Axil Protocol Team
 * @notice Comprehensive test suite for reward claiming functionality
 * @dev Covers access control, vesting periods, partial claims, max limits, and edge cases
 */
contract ClaimRewardsTest is Test {
    AxilProtocolV1 public axil;

    // ─────────────────────────────────────────────────────────────────────────
    // Test Actors
    // ─────────────────────────────────────────────────────────────────────────
    address public admin = address(0x1);
    address public user = address(0x2);
    address public attacker = address(0x999);

    // ─────────────────────────────────────────────────────────────────────────
    // Signer Configuration (EIP-712)
    // ─────────────────────────────────────────────────────────────────────────
    uint256 constant SIGNER_KEY = 0xA1;
    address public signer;

    // ─────────────────────────────────────────────────────────────────────────
    // Protocol Constants
    // ─────────────────────────────────────────────────────────────────────────
    uint128 constant INITIAL_REWARDS = 10 ether;
    uint128 constant MAX_CLAIM_LIMIT = 5 ether;
    uint256 constant VESTING_BLOCKS = 7200;

    // ─────────────────────────────────────────────────────────────────────────
    // Events
    // ─────────────────────────────────────────────────────────────────────────
    event RewardsClaimed(address indexed recipient, uint256 amount, bytes32 indexed intentId);
    event RewardAccrued(address indexed recipient, uint256 amount, bytes32 indexed category, uint64 releaseBlock);

    // ─────────────────────────────────────────────────────────────────────────
    // Setup
    // ─────────────────────────────────────────────────────────────────────────
    function setUp() public {
        signer = vm.addr(SIGNER_KEY);

        vm.startPrank(admin);
        axil = new AxilProtocolV1(admin, signer, address(0x6), address(0x7), address(0x8), keccak256("SALT"));
        vm.stopPrank();

        vm.deal(user, 100_000 ether);
        vm.deal(address(this), 100_000 ether);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // EIP-712 Helpers
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Returns the EIP-712 domain separator
    function _getDomainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("AxilProtocolV1")),
                keccak256(bytes("1")),
                block.chainid,
                address(axil)
            )
        );
    }

    /// @notice Builds EIP-712 signature for execute transaction
    function _buildExecuteSignature(address recipient, bytes32 intentId, uint128 amount, uint256 deadline, uint128 salt)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "Execute(address merchant,address user,bytes32 packedIntent,uint128 amount,uint256 deadline,uint128 salt,address agent)"
                ),
                admin,
                recipient,
                intentId,
                amount,
                deadline,
                salt,
                address(this)
            )
        );

        bytes32 finalHash = keccak256(abi.encodePacked("\x19\x01", _getDomainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, finalHash);

        return abi.encodePacked(r, s, v);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Reward Accrual Helper
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Helper to accrue rewards via execute() with unique intent per call
    function _accrueRewards(address recipient, uint128 amount, bytes32 uniqueSalt) internal returns (bytes32) {
        bytes32 intentId = keccak256(abi.encodePacked(uniqueSalt, "rewards"));
        uint256 deadline = block.timestamp + 1000;
        uint128 salt = uint128(uint256(uniqueSalt));

        bytes memory signature = _buildExecuteSignature(recipient, intentId, amount, deadline, salt);

        vm.deal(address(this), amount);
        vm.prank(address(this));
        axil.execute{value: amount}(admin, recipient, intentId, deadline, salt, signature);

        return intentId;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Tests
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Should successfully claim full rewards after vesting period
    function test_ClaimRewards_Success() public {
        _accrueRewards(user, INITIAL_REWARDS, keccak256("test1"));

        (uint128 totalBefore, uint64 releaseBlock,,) = axil.getRewardVault(user);
        assertTrue(totalBefore > 0, "Rewards should be accrued");
        assertTrue(releaseBlock > uint64(block.number), "Release block should be in future");

        vm.roll(block.number + VESTING_BLOCKS + 1);

        vm.prank(user);
        vm.expectEmit(true, true, false, true);
        emit RewardsClaimed(user, totalBefore, keccak256("claim-1"));

        axil.claimRewards(totalBefore, keccak256("claim-1"));

        (uint128 totalAfter,,,) = axil.getRewardVault(user);
        assertEq(totalAfter, 0, "All rewards should be claimed");
    }

    /// @notice Should revert when claiming before vesting period ends
    function test_RevertWhen_ClaimBeforeRelease() public {
        _accrueRewards(user, INITIAL_REWARDS, keccak256("test2"));

        (uint128 totalBefore,,,) = axil.getRewardVault(user);
        assertTrue(totalBefore > 0, "Rewards should be accrued before test");

        vm.prank(user);
        vm.expectRevert(AxilProtocolV1.Axil__ClaimFailed.selector);
        axil.claimRewards(totalBefore, keccak256("claim-2"));
    }

    /// @notice Should revert when claiming more than available balance
    function test_RevertWhen_ClaimAmountTooHigh() public {
        _accrueRewards(user, INITIAL_REWARDS, keccak256("test3"));

        (uint128 totalBefore,,,) = axil.getRewardVault(user);

        vm.roll(block.number + VESTING_BLOCKS + 1);

        uint128 tooMuch = totalBefore + 1 ether;

        vm.prank(user);
        vm.expectRevert(AxilProtocolV1.Axil__InvalidAmount.selector);
        axil.claimRewards(tooMuch, keccak256("claim-3"));
    }

    /// @notice Should revert when no rewards are pending for the caller
    function test_RevertWhen_NoRewards() public {
        vm.prank(user);
        vm.expectRevert(AxilProtocolV1.Axil__NoPendingRewards.selector);
        axil.claimRewards(1 ether, keccak256("claim-4"));
    }

    /// @notice Should enforce max claim limit per transaction
    function test_ClaimLimit() public {
        vm.prank(admin);
        axil.updateConfig(AxilProtocolV1.ConfigKey.MaxClaim, MAX_CLAIM_LIMIT, address(0));

        // Make 10 payments of 1000 ETH each = 10,000 ETH total
        // Reward per payment = 1000 * 0.008 = 8 ETH
        // Total rewards = 80 ETH, which is definitely > 5 ETH limit
        for (uint256 i = 0; i < 10; i++) {
            _accrueRewards(user, 1000 ether, keccak256(abi.encodePacked("limit", i)));
            vm.warp(block.timestamp + 1); // Ensure unique salt
        }

        (uint128 totalBefore,,,) = axil.getRewardVault(user);
        assertTrue(totalBefore > MAX_CLAIM_LIMIT, "Should have more than limit");

        vm.roll(block.number + VESTING_BLOCKS + 1);

        vm.prank(user);
        axil.claimRewards(totalBefore, keccak256("claim-5"));

        (uint128 remaining,,,) = axil.getRewardVault(user);
        assertEq(remaining, totalBefore - MAX_CLAIM_LIMIT, "Should have remaining rewards");
    }

    /// @notice Should allow partial claims and keep the rest in vault
    function test_PartialClaim() public {
        _accrueRewards(user, 20 ether, keccak256("partial"));

        (uint128 totalBefore,,,) = axil.getRewardVault(user);

        vm.roll(block.number + VESTING_BLOCKS + 1);

        uint128 claimAmount = totalBefore / 2;
        vm.prank(user);
        axil.claimRewards(claimAmount, keccak256("claim-6"));

        (uint128 remaining,,,) = axil.getRewardVault(user);
        assertEq(remaining, totalBefore - claimAmount, "Should have remaining rewards");
    }

    /// @notice Claiming with amount 0 should claim all pending rewards
    function test_ClaimZeroClaimsAll() public {
        _accrueRewards(user, 7 ether, keccak256("zero"));

        (uint128 totalBefore,,,) = axil.getRewardVault(user);
        assertTrue(totalBefore > 0, "Should have rewards before claim");

        vm.roll(block.number + VESTING_BLOCKS + 1);

        vm.prank(user);
        axil.claimRewards(0, keccak256("claim-7"));

        (uint128 remaining,,,) = axil.getRewardVault(user);
        assertEq(remaining, 0, "All rewards should be claimed");
    }

    /// @notice IntentId in event can be arbitrary and does not affect logic
    function test_ClaimWithAnyIntentId() public {
        _accrueRewards(user, 5 ether, keccak256("any"));

        vm.roll(block.number + VESTING_BLOCKS + 1);

        (uint128 balance,,,) = axil.getRewardVault(user);

        vm.prank(user);
        vm.expectEmit(true, true, false, true);
        emit RewardsClaimed(user, balance, keccak256("custom-intent-id"));
        axil.claimRewards(balance, keccak256("custom-intent-id"));
    }

    /// @notice Only the reward owner should be able to claim
    function test_RevertWhen_NonUserClaims() public {
        _accrueRewards(user, 5 ether, keccak256("owner"));

        vm.roll(block.number + VESTING_BLOCKS + 1);

        (uint128 balance,,,) = axil.getRewardVault(user);
        assertTrue(balance > 0, "User should have rewards");

        vm.prank(attacker);
        vm.expectRevert();
        axil.claimRewards(balance, keccak256("claim-8"));
    }

    /// @notice Should revert if trying to claim the same rewards twice
    function test_RevertWhen_ClaimTwice() public {
        _accrueRewards(user, 5 ether, keccak256("twice"));

        vm.roll(block.number + VESTING_BLOCKS + 1);

        (uint128 balance,,,) = axil.getRewardVault(user);
        assertTrue(balance > 0, "User should have rewards before first claim");

        vm.prank(user);
        axil.claimRewards(balance, keccak256("claim-9"));

        vm.prank(user);
        vm.expectRevert(AxilProtocolV1.Axil__NoPendingRewards.selector);
        axil.claimRewards(balance, keccak256("claim-9"));
    }

    /// @notice Verify reward amount calculation matches expected 0.2% fee
    function test_RewardCalculation() public {
        uint128 paymentAmount = 1000 ether;
        uint128 expectedReward = paymentAmount / 500; // 0.2% = 1/500

        _accrueRewards(user, paymentAmount, keccak256("calc"));

        (uint128 totalAfter,,,) = axil.getRewardVault(user);
        assertApproxEqAbs(totalAfter, expectedReward, 1, "Reward should be approximately 0.2% of payment");
    }
}
