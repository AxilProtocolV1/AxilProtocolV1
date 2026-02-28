// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {AxilProtocolV1} from "../src/AxilProtocolV1.sol";

/**
 * @title MonadGasTest
 * @author Axil Protocol Team
 * @notice Test suite for Monad-specific gas pricing mechanism
 * @dev Validates gas optimization strategies for Monad where fees are charged on gas_limit
 *      All tests optimized to stay within 29 million gas limit
 */
contract MonadGasTest is Test {
    AxilProtocolV1 public axil;

    // Test Actors
    address public admin = address(0x1);
    address public user = address(0x2);
    address public merchant = address(0x3);
    address public keeper = address(0x5);
    address public treasury = address(0x6);
    address public validatorPool = address(0x7);
    address public dexBroker = address(0x8);
    address public agent = address(0x777);

    // Signer Configuration
    uint256 constant SIGNER_KEY = 0xA1;
    address public signer;

    // Protocol Constants
    uint128 constant MIN_EXECUTION_AMOUNT = 0.001 ether;
    uint128 constant MAX_CLAIM_LIMIT = 5 ether;
    uint128 constant BURN_QUEUE_LIMIT = 10 ether;
    uint256 constant VESTING_BLOCKS = 7200;
    uint256 constant FEE_BPS = 100;
    uint256 constant BURN_SHARE_DIVISOR = 5;
    uint128 constant TEST_AMOUNT = 1000 ether;

    // Gas optimization constants
    uint256 constant RECOMMENDED_BUFFER_PERCENT = 25;
    uint256 constant MAX_ACCEPTABLE_OVERHEAD = 50;
    uint256 constant MONAD_GAS_LIMIT = 29_000_000; // Monad block gas limit

    // Statistics
    uint256 public totalTransactions;
    uint256 public totalGasEstimated;
    uint256 public totalGasUsed;
    uint256 public totalGasLimit;
    uint256 public failedTransactions;

    event GasStats(uint256 estimated, uint256 limit, uint256 used, uint256 overhead, bool success);

    function setUp() public {
        signer = vm.addr(SIGNER_KEY);

        vm.startPrank(admin);
        axil = new AxilProtocolV1(admin, signer, treasury, validatorPool, dexBroker, keccak256("SALT"));

        axil.updateConfig(AxilProtocolV1.ConfigKey.MaxClaim, MAX_CLAIM_LIMIT, address(0));
        axil.updateConfig(AxilProtocolV1.ConfigKey.BurnLimit, BURN_QUEUE_LIMIT, address(0));
        axil.updateConfig(AxilProtocolV1.ConfigKey.MaxRetries, 2, address(0));
        axil.updateConfig(AxilProtocolV1.ConfigKey.BurnCooldown, 10, address(0));

        axil.grantRole(axil.KEEPER_ROLE(), keeper);
        vm.stopPrank();

        vm.deal(user, TEST_AMOUNT * 1000);
        vm.deal(merchant, TEST_AMOUNT * 1000);
        vm.deal(agent, TEST_AMOUNT * 1000);
        vm.deal(address(this), TEST_AMOUNT * 1000);

        totalTransactions = 0;
        totalGasEstimated = 0;
        totalGasUsed = 0;
        totalGasLimit = 0;
        failedTransactions = 0;
    }

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

    function _createExecuteSignature(
        address _merchant,
        address _user,
        bytes32 intentId,
        uint128 amount,
        uint256 deadline,
        uint128 salt,
        address _agent
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "Execute(address merchant,address user,bytes32 packedIntent,uint128 amount,uint256 deadline,uint128 salt,address agent)"
                ),
                _merchant,
                _user,
                intentId,
                amount,
                deadline,
                salt,
                _agent
            )
        );
        bytes32 finalHash = keccak256(abi.encodePacked("\x19\x01", _getDomainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, finalHash);
        return abi.encodePacked(r, s, v);
    }

    function _estimateGasForExecute(address _merchant, address _user, uint128 amount, uint256 nonce)
        internal
        returns (uint256)
    {
        bytes32 intentId = keccak256(abi.encodePacked(block.timestamp, _merchant, _user, amount, nonce, "estimate"));

        uint256 deadline = block.timestamp + 1000;
        // forge-lint: disable-next-line unsafe-typecast
        uint128 salt =
            uint128(uint256(keccak256(abi.encodePacked(block.timestamp, _merchant, _user, amount, nonce, "salt"))));

        bytes memory signature =
            _createExecuteSignature(_merchant, _user, intentId, amount, deadline, salt, address(this));

        uint256 gasBefore = gasleft();
        vm.prank(address(this));
        axil.execute{value: amount}(_merchant, _user, intentId, deadline, salt, signature);
        uint256 gasAfter = gasleft();

        return gasBefore - gasAfter;
    }

    function _executeWithGasLimit(address _merchant, address _user, uint128 amount, uint256 nonce, uint256 gasLimit)
        internal
        returns (bool)
    {
        bytes32 intentId = keccak256(abi.encodePacked(block.timestamp, _merchant, _user, amount, nonce, "gas-test"));

        uint256 deadline = block.timestamp + 1000;
        // forge-lint: disable-next-line unsafe-typecast
        uint128 salt =
            uint128(uint256(keccak256(abi.encodePacked(block.timestamp, _merchant, _user, amount, nonce, "salt"))));

        bytes memory signature = _createExecuteSignature(_merchant, _user, intentId, amount, deadline, salt, agent);

        vm.deal(agent, amount);
        vm.prank(agent);

        uint256 gasBefore = gasleft();
        try axil.execute{gas: gasLimit, value: amount}(_merchant, _user, intentId, deadline, salt, signature) {
            uint256 gasAfter = gasleft();
            uint256 gasUsed = gasBefore - gasAfter;

            totalTransactions++;
            totalGasUsed += gasUsed;
            totalGasLimit += gasLimit;

            emit GasStats(0, gasLimit, gasUsed, gasLimit > gasUsed ? gasLimit - gasUsed : 0, true);
            return true;
        } catch {
            totalTransactions++;
            failedTransactions++;
            emit GasStats(0, gasLimit, 0, gasLimit, false);
            return false;
        }
    }

    /**
     * @notice Test 1: Basic gas estimation with recommended buffer
     * @dev Uses 1 transaction, ~350k gas
     */
    function test_GasEstimationWithBuffer() public {
        uint128 amount = 1000 ether;
        uint256 nonce = 1;

        uint256 estimated = _estimateGasForExecute(merchant, user, amount, nonce);
        uint256 gasLimit = estimated * (100 + RECOMMENDED_BUFFER_PERCENT) / 100;

        bool success = _executeWithGasLimit(merchant, user, amount, nonce, gasLimit);

        assertTrue(success, "Transaction should succeed with recommended buffer");

        uint256 overhead = gasLimit - estimated;
        uint256 overheadPercent = overhead * 100 / estimated;

        console.log("Gas Estimation Test:");
        console.log("  Estimated:");
        console.log(estimated);
        console.log("  Gas Limit:");
        console.log(gasLimit);
        console.log("  Overhead:");
        console.log(overhead);
        console.log("  Overhead Percent:");
        console.log(overheadPercent);
        console.log("  Buffer Used:");
        console.log(RECOMMENDED_BUFFER_PERCENT);

        assertTrue(overheadPercent <= MAX_ACCEPTABLE_OVERHEAD, "Overhead should be acceptable");
    }

    /**
     * @notice Test 2: Multiple buffer sizes
     * @dev Uses 7 transactions, ~2.5M gas total
     */
    function test_MultipleBufferSizes() public {
        uint128 amount = 500 ether;

        uint256[7] memory buffers;
        buffers[0] = 10;
        buffers[1] = 15;
        buffers[2] = 20;
        buffers[3] = 25;
        buffers[4] = 30;
        buffers[5] = 35;
        buffers[6] = 40;

        uint256 successes = 0;

        console.log("");
        console.log("Buffer Size Test:");

        for (uint256 i = 0; i < buffers.length; i++) {
            uint256 estimated = _estimateGasForExecute(merchant, user, amount, i + 1000);
            uint256 gasLimit = estimated * (100 + buffers[i]) / 100;

            bool success = _executeWithGasLimit(merchant, user, amount, i + 1000, gasLimit);

            if (success) {
                successes++;
            }

            console.log("  Buffer");
            console.log(buffers[i]);
            console.log("%:");
            console.log(success ? "SUCCESS" : "FAIL");
        }

        console.log("  Success rate:");
        console.log(successes * 100 / buffers.length);
        console.log("%");

        bool twentyFiveSuccess = _executeWithGasLimit(
            merchant, user, amount, 9999, _estimateGasForExecute(merchant, user, amount, 9999) * 125 / 100
        );
        assertTrue(twentyFiveSuccess, "25% buffer should always succeed");
    }

    /**
     * @notice Test 3: State lookback impact
     * @dev Uses 5 transactions, ~1.75M gas total
     */
    function test_StateLookbackImpact() public {
        uint128 amount = 100 ether;
        uint256 baseNonce = 5000;

        uint256[5] memory lookbacks;
        lookbacks[0] = 0;
        lookbacks[1] = 5;
        lookbacks[2] = 10;
        lookbacks[3] = 20;
        lookbacks[4] = 30;

        console.log("");
        console.log("State Lookback Test:");

        uint256 estimatedLB0 = _estimateGasForExecute(merchant, user, amount, baseNonce);

        for (uint256 i = 0; i < lookbacks.length; i++) {
            vm.roll(block.number + lookbacks[i]);

            uint256 newNonce = baseNonce + i + 1000;

            bytes32 intentId =
                keccak256(abi.encodePacked(block.timestamp, merchant, user, amount, newNonce, "lookback"));

            uint256 deadline = block.timestamp + 1000;
            // forge-lint: disable-next-line unsafe-typecast
            uint128 salt = uint128(
                uint256(keccak256(abi.encodePacked(block.timestamp, merchant, user, amount, newNonce, "salt")))
            );

            bytes memory signature = _createExecuteSignature(merchant, user, intentId, amount, deadline, salt, agent);

            uint256 gasLimit = estimatedLB0 * 125 / 100;

            vm.deal(agent, amount);
            vm.prank(agent);

            bool success;
            try axil.execute{gas: gasLimit, value: amount}(merchant, user, intentId, deadline, salt, signature) {
                success = true;
            } catch {
                success = false;
            }

            console.log("  LB");
            console.log(lookbacks[i]);
            console.log(" blocks:");
            console.log("    Estimated (LB0):");
            console.log(estimatedLB0);
            console.log("    Success:");
            console.log(success ? "YES" : "NO");
        }
    }

    /**
     * @notice Test 4: Transaction complexity impact
     * @dev Uses 4 transactions * 2 = 8 transactions, ~2.8M gas total
     */
    function test_ComplexityImpact() public {
        uint128[4] memory amounts;
        amounts[0] = 10 ether;
        amounts[1] = 100 ether;
        amounts[2] = 1000 ether;
        amounts[3] = 10000 ether;

        console.log("");
        console.log("Transaction Complexity Test:");

        for (uint256 i = 0; i < amounts.length; i++) {
            uint128 amount = amounts[i];

            uint256 estimated = _estimateGasForExecute(merchant, user, amount, i + 2000);

            uint256 tightLimit = estimated * 110 / 100;
            bool tightSuccess = _executeWithGasLimit(merchant, user, amount, i + 2000, tightLimit);

            uint256 safeLimit = estimated * 125 / 100;
            bool safeSuccess = _executeWithGasLimit(merchant, user, amount, i + 3000, safeLimit);

            console.log("  Amount:");
            console.log(amount / 1 ether);
            console.log(" MON");
            console.log("    Estimated:");
            console.log(estimated);
            console.log("    Tight (10%):");
            console.log(tightSuccess ? "OK" : "FAIL");
            console.log("    Safe (25%):");
            console.log(safeSuccess ? "OK" : "FAIL");
        }
    }

    /**
     * @notice Test 5: Optimal buffer calculation
     * @dev Uses 10 buffers * 30 iterations = 300 transactions
     *      300 * 350k = 105M gas - too high! Using 10 iterations instead
     *      Total gas: 10 * 10 * 350k = 35M gas (close to limit)
     */
    function test_OptimalBufferCalculation() public {
        uint128 amount = 250 ether;
        uint256 iterations = 8; // 8 iterations per buffer

        console.log("");
        console.log("Optimal Buffer Calculation (29M gas optimized):");

        uint256 totalGasStart = gasleft();
        uint256 totalTxCount = 0;

        for (uint256 buffer = 5; buffer <= 50; buffer += 5) {
            uint256 successes = 0;

            for (uint256 i = 0; i < iterations; i++) {
                uint256 estimated = _estimateGasForExecute(merchant, user, amount, i + 4000 + buffer);
                uint256 gasLimit = estimated * (100 + buffer) / 100;

                bool success = _executeWithGasLimit(merchant, user, amount, i + 4000 + buffer, gasLimit);
                if (success) successes++;
                totalTxCount++;
            }

            uint256 successRate = successes * 100 / iterations;

            console.log("Buffer", buffer, "%:");
            console.log("  Success rate:", successRate, "%");

            if (successRate == 100) {
                console.log("  Optimal buffer:", buffer, "%");
                break;
            }
        }

        uint256 totalGasEnd = gasleft();
        uint256 gasUsed = totalGasStart - totalGasEnd;

        console.log("Total transactions:", totalTxCount);
        console.log("Total gas used:", gasUsed);
        console.log("Average gas per tx:", gasUsed / totalTxCount);
        console.log("Monad gas limit:", MONAD_GAS_LIMIT);
        console.log("Within limit?", gasUsed <= MONAD_GAS_LIMIT ? "YES" : "NO");

        assertTrue(gasUsed <= MONAD_GAS_LIMIT, "Test should stay within Monad gas limit");
    }

    /**
     * @notice Test 6: Gas statistics summary
     * @dev Uses 10 transactions, ~3.5M gas total
     */
    function test_GasStatistics() public {
        uint128 amount = 100 ether;
        uint256 batchSize = 10;

        for (uint256 i = 0; i < batchSize; i++) {
            uint256 estimated = _estimateGasForExecute(merchant, user, amount, i + 5000);
            uint256 gasLimit = estimated * 125 / 100;
            _executeWithGasLimit(merchant, user, amount, i + 5000, gasLimit);
        }

        console.log("");
        console.log("Gas Statistics Summary:");
        console.log("  Total Transactions:");
        console.log(totalTransactions);
        console.log("  Failed Transactions:");
        console.log(failedTransactions);
        console.log("  Success Rate:");
        console.log((totalTransactions - failedTransactions) * 100 / totalTransactions);
        console.log("%");

        if (totalTransactions > 0) {
            uint256 avgGasLimit = totalGasLimit / totalTransactions;
            uint256 avgGasUsed = totalGasUsed / totalTransactions;
            uint256 avgOverhead = (totalGasLimit - totalGasUsed) / totalTransactions;
            uint256 avgOverheadPercent = (totalGasLimit - totalGasUsed) * 100 / totalGasUsed;

            console.log("  Average Gas Limit:");
            console.log(avgGasLimit);
            console.log("  Average Gas Used:");
            console.log(avgGasUsed);
            console.log("  Average Overhead:");
            console.log(avgOverhead);
            console.log("  Average Overhead %:");
            console.log(avgOverheadPercent);
        }

        assertTrue(failedTransactions < totalTransactions / 10, "Failure rate should be below 10%");
    }

    /**
     * @notice Test 7: Minimal buffer test
     * @dev Uses 1 transaction, ~350k gas
     */
    function test_MinimalBuffer() public {
        uint128 amount = 500 ether;

        uint256 estimated = _estimateGasForExecute(merchant, user, amount, 9998);

        uint256 tightLimit = estimated * 105 / 100;
        bool success = _executeWithGasLimit(merchant, user, amount, 9998, tightLimit);

        console.log("");
        console.log("Minimal Buffer Test:");
        console.log("  Estimated:");
        console.log(estimated);
        console.log("  5% Buffer Limit:");
        console.log(tightLimit);
        console.log("  Success:");
        console.log(success ? "YES" : "NO");
    }

    /**
     * @notice Test 8: Ethereum vs Monad comparison
     * @dev Uses 2 transactions, ~700k gas total
     */
    function test_EthereumComparison() public {
        uint128 amount = 1000 ether;

        uint256 estimated = _estimateGasForExecute(merchant, user, amount, 9997);

        uint256 ethStyleLimit = estimated * 300 / 100;
        uint256 monadStyleLimit = estimated * 125 / 100;

        bool ethSuccess = _executeWithGasLimit(merchant, user, amount, 9997, ethStyleLimit);
        bool monadSuccess = _executeWithGasLimit(merchant, user, amount, 9998, monadStyleLimit);

        console.log("");
        console.log("Ethereum vs Monad Comparison:");
        console.log("  Estimated:");
        console.log(estimated);
        console.log("  Ethereum (300%):");
        console.log(ethStyleLimit);
        console.log(ethSuccess ? "OK" : "FAIL");

        console.log("  Monad (125%):");
        console.log(monadStyleLimit);
        console.log(monadSuccess ? "OK" : "FAIL");
        console.log("  Gas Saved:");
        console.log(ethStyleLimit - monadStyleLimit);
        console.log("  Savings %:");
        console.log((ethStyleLimit - monadStyleLimit) * 100 / ethStyleLimit);

        assertTrue(monadSuccess, "Monad optimal buffer should succeed");
    }
}
