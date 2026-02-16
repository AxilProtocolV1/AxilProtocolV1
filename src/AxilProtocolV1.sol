// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/interfaces/IERC1271.sol";


/**
 * @title AxilProtocolV1
 * @author Axil Protocol
 * @notice High-performance payment & settlement layer for AI agents on Monad
 * @dev Optimized for Monad's parallel execution - supports 10k+ TPS
 */
contract AxilProtocolV1 is EIP712, AccessControl, ReentrancyGuard, Pausable {
    using ECDSA for bytes32;

    /*//////////////////////////////////////////////////////////////
                        ERRORS
    //////////////////////////////////////////////////////////////*/
    error Axil__InsufficientPaymentAmount();
    error Axil__SignatureExpired();
    error Axil__IntentAlreadyExecuted();
    error Axil__InvalidSignature();
    error Axil__MerchantPaymentFailed();
    error Axil__BurnQueueFull();
    error Axil__InsufficientContractBalance();
    error Axil__ArrayLengthMismatch();
    error Axil__BurnCooldownActive();
    error Axil__ZeroAddressNotAllowed();
    error Axil__InvalidBitmapShift();
    error Axil__DeadlineTooShort();
    error Axil__BatchSizeExceeded();
    error Axil__ValueTooHigh();
    error Axil__InvalidIntent();
    error Axil__InvalidMask();
    error Axil__BatchProcessingPaused();
    error Axil__MaxRetriesExceeded();
    error Axil__UnauthorizedAccess();
    error Axil__InvalidAmount();
    error Axil__ClaimFailed();
    error Axil__NoPendingRewards();
    error Axil__SweepFailed();

/**
 * █████╗ ██╗  ██╗██╗██╗      ██████╗ ██████╗  ██████╗   
 * ██╔══██╗╚██╗██╔╝██║██║      ██╔══██╗██╔══██╗██╔═══██╗
 * ███████║ ╚███╔╝ ██║██║      ██████╔╝██████╔╝██║   ██║      
 * ██╔══██║ ██╔██╗ ██║██║      ██╔═══╝ ██╔══██╗██║   ██║     
 * ██║  ██║██╔╝ ██╗██║███████╗ ██║     ██║  ██║╚██████╔╝     
 * ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚══════╝ ╚═╝     ╚═╝  ╚═╝ ╚═════╝      
 */

    /*//////////////////////////////////////////////////////////////
                          ROLES
    //////////////////////////////////////////////////////////////*/
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant KEEPER_ROLE = keccak256("KEEPER_ROLE");
    bytes32 public constant TREASURY_ROLE = keccak256("TREASURY_ROLE");
    bytes32 public constant MERCHANT_ROLE = keccak256("MERCHANT_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    /*//////////////////////////////////////////////////////////////
                    IMMUTABLE CONFIGURATIONS
    //////////////////////////////////////////////////////////////*/
    address public immutable i_admin;
    address public immutable i_signer;
    address public immutable i_sweepReceiver;
    address public immutable i_validatorPool;
    address public immutable i_dexBroker;
    address public constant BURN_ADDRESS = 0x000000000000000000000000000000000000dEaD;
    
    /*//////////////////////////////////////////////////////////////
                      OPTIMIZED CONSTANTS
    //////////////////////////////////////////////////////////////*/
    uint128[4] public PACKED_CONSTANTS;
    bytes32 private constant EXECUTE_TYPEHASH = keccak256("Execute(address merchant,address user,bytes32 packedIntent,uint128 amount,uint256 deadline,uint128 salt,address agent)");
    bytes32 private constant CLAIM_TYPEHASH = keccak256("Claim(address account,uint128 amount,bytes32 intentId,uint256 deadline)");

   /*//////////////////////////////////////////////////////////////
                    ENUMS & STRUCTS
   //////////////////////////////////////////////////////////////*/
    
    enum ConfigKey { MaxClaim, BatchIter, Signer, Sweep, BurnLimit, UseAllowlist, BurnCooldown, MinExecution, MaxRetries }
    
    struct SystemConfig {
        address signerAddress;
        address sweepReceiver;
        uint128 minExecutionAmount;
        uint128 maxClaimLimit;

uint128 maxBurnQueueLimit;
        uint32 batchMaxIterations;
        uint32 useMerchantAllowlist;
        uint32 burnCooldownActive;
        uint32 maxRetryAttempts;
    }
    
    struct RewardVault {
        uint128 totalAmount;
        uint64 releaseBlock;
        uint64 lastClaimed;
        uint8 retryCount;
    }

    /*//////////////////////////////////////////////////////////////
                     OPTIMIZED STORAGE SLOTS
    //////////////////////////////////////////////////////////////*/
    struct SlotA { 
        uint128 failedBurnQueue; 
        uint128 totalBurned; 
    }
    struct SlotB { 
        uint128 totalPendingRewards; 
        uint64 lastBurnRetryBlock; 
        uint64 lastBurnRetryTimestamp;
        uint64 lastBatchProcessed;
    }
    
    SlotA public slotA;
    SlotB public slotB;

    /*//////////////////////////////////////////////////////////////
                    STORAGE
    //////////////////////////////////////////////////////////////*/
    bytes32[4] private i_rewardCategories;
    bytes32 private immutable i_domainSalt;
    SystemConfig public config;
    mapping(uint128 => uint128) public intentBitmap;
    mapping(address => RewardVault) public pendingRewards;
    mapping(address => uint256) public keeperResumeIndex;
    mapping(address => uint256) public lastActivity;
    mapping(bytes32 => bool) public intentProcessed;
    bool public batchProcessingPaused;
    uint256 public totalExecutedIntents;
    uint256 public totalValueProcessed;

    /*//////////////////////////////////////////////////////////////
                    BACKWARD COMPATIBILITY GETTERS
    //////////////////////////////////////////////////////////////*/
    function failedBurnQueue() external view returns (uint128) { return slotA.failedBurnQueue; }
    function totalBurned() external view returns (uint128) { return slotA.totalBurned; }
    function totalPendingRewards() external view returns (uint128) { return slotB.totalPendingRewards; }
    function lastBurnRetryBlock() external view returns (uint64) { return slotB.lastBurnRetryBlock; }

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/
    
    event AdminTransferred(address indexed oldAdmin, address indexed newAdmin);
    event EmergencyTransferred(address indexed oldEmergency, address indexed newEmergency);
    event IntentSettled(uint128 indexed bucket, uint128 indexed mask, address indexed merchant, address agent, uint256 amount, bytes32 intentId);
    event FeeDistributed(uint256 rewardShare, uint256 burnShare, uint256 merchantShare);
    event RewardAccrued(address indexed recipient, uint256 amount, bytes32 indexed category, uint64 releaseBlock);
    event RewardsClaimed(address indexed recipient, uint256 amount, bytes32 indexed intentId);
    event ClaimFailed(address indexed recipient, uint256 amount, bytes32 indexed intentId, uint8 retryCount);
    event BatchClaimProgress(address indexed keeper, uint256 nextIndex, uint256 processed, uint256 gasRemaining);
    event BurnExecuted(uint256 amount, bool success);
    event BurnQueueUpdated(uint256 newAmount, bool added);
    event BurnQueueCritical(uint256 currentAmount, uint256 limit);
    event ConfigUpdated(uint8 indexed parameter, uint256 newValue, address newAddr);
    event EmergencySweep(uint256 amount, address indexed receiver);
    event BatchProcessingToggled(bool paused);
    event IntentValidated(address indexed merchant, address indexed user, bytes32 indexed intentId);
    event EmergencyPaused(address indexed executor);
    event EmergencyUnpaused(address indexed executor);

    /*//////////////////////////////////////////////////////////////
                        CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/
    constructor(address _admin, address _signer, address _sweepReceiver, address _validatorPool, address _dexBroker, bytes32 _salt) EIP712("AxilProtocolV1", "1") {

       if (_admin == address(0) || _signer == address(0) ||  _sweepReceiver == address(0) || _validatorPool == address(0) || _dexBroker == address(0)) revert Axil__ZeroAddressNotAllowed();
i_admin = _admin; i_signer = _signer; i_sweepReceiver = _sweepReceiver; i_validatorPool = _validatorPool; i_dexBroker = _dexBroker; i_domainSalt = _salt;
       
        PACKED_CONSTANTS = [uint128(5 minutes), uint128(100), uint128(7200), uint128(100)];
        i_rewardCategories = [keccak256("AGENT"), keccak256("USER"), keccak256("VALIDATOR"), keccak256("BROKER")];
        _grantRole(DEFAULT_ADMIN_ROLE, _admin); _grantRole(ADMIN_ROLE, _admin); _grantRole(TREASURY_ROLE, _sweepReceiver); _grantRole(KEEPER_ROLE, _admin); _grantRole(EMERGENCY_ROLE, _admin);
        config = SystemConfig({
            signerAddress: _signer, 
            sweepReceiver: _sweepReceiver, 
            minExecutionAmount: _toU128(0.001 ether), 
            maxClaimLimit: _toU128(5 ether), 
            maxBurnQueueLimit: _toU128(10 ether), 
            batchMaxIterations: 50, 
            useMerchantAllowlist: 0, 
            burnCooldownActive: 60,
            maxRetryAttempts: 3
        });
        slotA = SlotA(0, 0); 
        slotB = SlotB(0, 0, 0, 0);
        batchProcessingPaused = false;
    }

    /*//////////////////////////////////////////////////////////////
                                    INTERNAL HELPERS
    //////////////////////////////////////////////////////////////*/
    function _toU128(uint256 v) internal pure returns (uint128) {
        if (v > type(uint128).max) revert Axil__ValueTooHigh();
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint128(v);
    }
    
    function _minDeadlineBuffer() internal view returns (uint256) { return uint256(PACKED_CONSTANTS[0]); }
    function _feeBps() internal view returns (uint256) { return uint256(PACKED_CONSTANTS[1]); }
    function _vestingBlocks() internal view returns (uint64) { return uint64(PACKED_CONSTANTS[2]); }
    function _maxBatchSize() internal view returns (uint256) { return uint256(PACKED_CONSTANTS[3]); }
    
    function packIntent(uint128 bucket, uint128 mask) public pure returns (bytes32) { 
        if (bucket == 0 && mask == 0) revert Axil__InvalidIntent();
        if (mask == 0) revert Axil__InvalidMask();
        return bytes32(uint256(bucket) << 128 | uint256(mask)); 
    }
    
    function unpackIntent(bytes32 packed) public pure returns (uint128 bucket, uint128 mask) { 
        uint256 val = uint256(packed); 
        // forge-lint: disable-next-line(unsafe-typecast)
        bucket = uint128(val >> 128); 
        // forge-lint: disable-next-line(unsafe-typecast)
        mask = uint128(val); 
    }

    function _validateIntent(bytes32 packedIntent) internal pure returns (uint128 bucket, uint128 mask) {
        (bucket, mask) = unpackIntent(packedIntent);
        if (bucket == 0 && mask == 0) revert Axil__InvalidIntent();
        if (mask == 0) revert Axil__InvalidMask();
        return (bucket, mask);
    }

    /*//////////////////////////////////////////////////////////////
                                MODIFIERS
    //////////////////////////////////////////////////////////////*/
    modifier whenBatchProcessingNotPaused() {
        if (batchProcessingPaused) revert Axil__BatchProcessingPaused();
        _;
    }

    modifier validAmount(uint256 amount) {
        if (amount == 0) revert Axil__InvalidAmount();
        _;
    }

    /*//////////////////////////////////////////////////////////////
                        CORE EXECUTION ENGINE
    //////////////////////////////////////////////////////////////*/
    function execute(
        address merchant, 
        address user, 
        bytes32 packedIntent, 
        uint256 deadline, 
        uint128 salt, 
        bytes calldata signature
    ) external payable whenNotPaused nonReentrant validAmount(msg.value) {
        if (config.useMerchantAllowlist > 0 && !hasRole(MERCHANT_ROLE, merchant)) revert Axil__UnauthorizedAccess();

if (msg.value < config.minExecutionAmount) revert Axil__InsufficientPaymentAmount();
        if (block.timestamp > deadline) revert Axil__SignatureExpired();
        if (deadline < block.timestamp + _minDeadlineBuffer()) revert Axil__DeadlineTooShort();
        
        (uint128 bucket, uint128 mask) = _validateIntent(packedIntent);
        
        if ((intentBitmap[bucket] & mask) != 0) revert Axil__IntentAlreadyExecuted();
        if (intentProcessed[packedIntent]) revert Axil__IntentAlreadyExecuted();
        
        _verifySignature(merchant, user, packedIntent, _toU128(msg.value), deadline, salt, signature);
        
        intentBitmap[bucket] |= mask;
        intentProcessed[packedIntent] = true;
        totalExecutedIntents++;
        totalValueProcessed += msg.value;
        lastActivity[msg.sender] = block.timestamp;
        
        _distributeFunds(merchant, user, msg.value);
        
        emit IntentSettled(bucket, mask, merchant, msg.sender, msg.value, packedIntent);
        emit IntentValidated(merchant, user, packedIntent);
    }

    function _distributeFunds(address merchant, address user, uint256 amount) internal {
        uint256 feeBps = _feeBps();
        uint256 fee = (amount * feeBps) / 10000;
        
        if (amount <= fee) revert Axil__InsufficientPaymentAmount();
        
        uint256 merchantShare = amount - fee;
        if (merchantShare < config.minExecutionAmount) {
            uint256 deficit = uint256(config.minExecutionAmount) - merchantShare;
            if (deficit > fee) revert Axil__InsufficientPaymentAmount();
            merchantShare = uint256(config.minExecutionAmount);
            fee = amount - merchantShare;
        }
        
        uint256 burnShare = fee / 5;
        uint256 rewardShare = fee - burnShare;
        
        if (rewardShare > 0) {
            _handleBurn(burnShare);
            _distributeRewards(rewardShare, user);
        }
        
        (bool success, ) = payable(merchant).call{value: merchantShare}("");
        if (!success) revert Axil__MerchantPaymentFailed();
        
        emit FeeDistributed(rewardShare, burnShare, merchantShare);
    }

    function _distributeRewards(uint256 rewardShare, address user) internal {
        if (rewardShare < 4) {
            _accrue(msg.sender, rewardShare, i_rewardCategories[0]);
            return;
        }
        
        address[4] memory recipients = [msg.sender, user, i_validatorPool, i_dexBroker];
        uint256 individualShare = rewardShare / 4;
        uint256 remainingShare = rewardShare - (individualShare * 3);
        
        for (uint256 i = 0; i < 4; i++) {
            uint256 share = (i == 3) ? remainingShare : individualShare;
            if (share > 0) {
                _accrue(recipients[i], share, i_rewardCategories[i]);
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                                        BATCH PROCESSING ENGINE
    //////////////////////////////////////////////////////////////*/
    function autoBatchClaim(
        address[] calldata accounts, 
        bytes32[] calldata intents, 
        uint128 gasThreshold
    ) external onlyRole(KEEPER_ROLE) nonReentrant whenNotPaused whenBatchProcessingNotPaused {
        if (accounts.length != intents.length) revert Axil__ArrayLengthMismatch();
        if (accounts.length > _maxBatchSize()) revert Axil__BatchSizeExceeded();
        
        uint256 i = keeperResumeIndex[msg.sender];
        if (i >= accounts.length) i = 0;
        
        uint256 processed = 0;
        uint256 limit = config.batchMaxIterations;
        uint256 gasThresholdValue = gasThreshold;
        
        while (i < accounts.length && gasleft() > gasThresholdValue && processed < limit) {
            _internalClaim(accounts[i], intents[i]);


 unchecked { 
                i++; 
                processed++; 
            }
        }
        
        keeperResumeIndex[msg.sender] = (i == accounts.length) ? 0 : i;
        slotB.lastBatchProcessed = uint64(block.number);
        
        emit BatchClaimProgress(msg.sender, keeperResumeIndex[msg.sender], processed, gasleft());
    }

    function toggleBatchProcessing() external onlyRole(ADMIN_ROLE) {
        batchProcessingPaused = !batchProcessingPaused;
        emit BatchProcessingToggled(batchProcessingPaused);
    }

    /*//////////////////////////////////////////////////////////////
                                        BURN MECHANISM
    //////////////////////////////////////////////////////////////*/
    function _handleBurn(uint256 amount) internal {
        if (amount == 0) return;
        
        (bool success, ) = payable(BURN_ADDRESS).call{value: amount}("");
        
        if (success) { 
            slotA.totalBurned += _toU128(amount); 
            emit BurnExecuted(amount, true); 
            return; 
        }
        
        uint128 newQueue = slotA.failedBurnQueue + _toU128(amount);
        if (newQueue > config.maxBurnQueueLimit) revert Axil__BurnQueueFull();
        
        slotA.failedBurnQueue = newQueue; 
        emit BurnQueueUpdated(newQueue, true);
        emit BurnExecuted(amount, false);
    }

    function autoRetryBurn(uint256 maxToBurn) external onlyRole(KEEPER_ROLE) nonReentrant {
        if (config.burnCooldownActive > 0) {
            if (block.number <= slotB.lastBurnRetryBlock || 
                block.timestamp <= uint256(slotB.lastBurnRetryTimestamp) + config.burnCooldownActive) {
                revert Axil__BurnCooldownActive();
            }
        }
        
        uint128 amountToBurn;
        if (maxToBurn > 0 && slotA.failedBurnQueue > maxToBurn) {
            amountToBurn = _toU128(maxToBurn);
        } else {
            amountToBurn = slotA.failedBurnQueue;
        }
        
        if (amountToBurn == 0) return;
        
        slotB.lastBurnRetryBlock = uint64(block.number);
        slotB.lastBurnRetryTimestamp = uint64(block.timestamp);
        slotA.failedBurnQueue -= amountToBurn;
        
        (bool success, ) = payable(BURN_ADDRESS).call{value: amountToBurn}("");
        
        if (success) { 
            slotA.totalBurned += amountToBurn; 
            emit BurnExecuted(amountToBurn, true); 
        } else { 
            slotA.failedBurnQueue += amountToBurn;
            emit BurnExecuted(amountToBurn, false);
        }
    }

    function checkBurnQueueCritical() external view returns (bool isCritical, uint256 currentAmount, uint256 limit) {
        currentAmount = slotA.failedBurnQueue;
        limit = config.maxBurnQueueLimit;
        isCritical = currentAmount >= limit / 2;
        return (isCritical, currentAmount, limit);
    }

    /*//////////////////////////////////////////////////////////////
                                        REWARD CLAIMS & SIGNATURES
    //////////////////////////////////////////////////////////////*/
    function _internalClaim(address account, bytes32 intentId) internal {
        RewardVault storage vault = pendingRewards[account];
        
        if (vault.totalAmount == 0) return;
        if (block.number < vault.releaseBlock) return;
        
        uint128 claimAmount = vault.totalAmount;
        if (claimAmount > config.maxClaimLimit) {
            claimAmount = config.maxClaimLimit;
        }
        
        if (claimAmount == 0) return;
        
        vault.totalAmount -= claimAmount;
        slotB.totalPendingRewards -= claimAmount;
        
        (bool success, ) = payable(account).call{value: claimAmount}("");
        
        if (!success) {
            vault.totalAmount += claimAmount;

           slotB.totalPendingRewards += claimAmount;
            vault.retryCount++;
            
            if (vault.retryCount >= config.maxRetryAttempts) {
                _handleBurn(claimAmount);
                emit ClaimFailed(account, claimAmount, intentId, vault.retryCount);
            } else {
                emit ClaimFailed(account, claimAmount, intentId, vault.retryCount);
            }
        } else {
            vault.lastClaimed = uint64(block.timestamp);
            vault.retryCount = 0;
            emit RewardsClaimed(account, claimAmount, intentId);
        }
    }

    function claimRewards(uint128 amount, bytes32 intentId) external nonReentrant whenNotPaused {
        RewardVault storage vault = pendingRewards[msg.sender];
        
        if (vault.totalAmount == 0) revert Axil__NoPendingRewards();
        if (block.number < vault.releaseBlock) revert Axil__ClaimFailed();
        
        uint128 claimAmount = amount > 0 ? amount : vault.totalAmount;
        if (claimAmount > vault.totalAmount) revert Axil__InvalidAmount();
        if (claimAmount > config.maxClaimLimit) claimAmount = config.maxClaimLimit;
        
        vault.totalAmount -= claimAmount;
        slotB.totalPendingRewards -= claimAmount;
        
        (bool success, ) = payable(msg.sender).call{value: claimAmount}("");
        
        if (!success) {
            vault.totalAmount += claimAmount;
            slotB.totalPendingRewards += claimAmount;
            revert Axil__ClaimFailed();
        }
        
        vault.lastClaimed = uint64(block.timestamp);
        emit RewardsClaimed(msg.sender, claimAmount, intentId);
    }

    function claimWithSignature(
        uint128 amount, 
        bytes32 intentId, 
        uint256 deadline, 
        bytes calldata signature
    ) external nonReentrant whenNotPaused {
        if (block.timestamp > deadline) revert Axil__SignatureExpired();
        
        bytes32 hash = _hashTypedDataV4(keccak256(abi.encode(
            CLAIM_TYPEHASH, 
            msg.sender, 
            amount, 
            intentId, 
            deadline
        )));
        
        address signer = config.signerAddress;
        if (signer.code.length > 0) { 
            if (IERC1271(signer).isValidSignature(hash, signature) != 0x1626ba7e) revert Axil__InvalidSignature(); 
        } else { 
            if (hash.recover(signature) != signer) revert Axil__InvalidSignature(); 
        }
        
        RewardVault storage vault = pendingRewards[msg.sender];
        if (vault.totalAmount == 0) revert Axil__NoPendingRewards();
        if (block.number < vault.releaseBlock) revert Axil__ClaimFailed();
        
        uint128 claimAmount = amount > 0 ? amount : vault.totalAmount;
        if (claimAmount > vault.totalAmount) revert Axil__InvalidAmount();
        if (claimAmount > config.maxClaimLimit) claimAmount = config.maxClaimLimit;
        
        vault.totalAmount -= claimAmount;
        slotB.totalPendingRewards -= claimAmount;
        
        (bool success, ) = payable(msg.sender).call{value: claimAmount}("");
        if (!success) revert Axil__ClaimFailed();
        
        vault.lastClaimed = uint64(block.timestamp);
        emit RewardsClaimed(msg.sender, claimAmount, intentId);
    }

    function _accrue(address to, uint256 amount, bytes32 category) internal {
        if (amount == 0) return;
        
        RewardVault storage vault = pendingRewards[to];
        vault.totalAmount += _toU128(amount);
        slotB.totalPendingRewards += _toU128(amount);
        
        uint64 newRelease = uint64(block.number + _vestingBlocks());
        if (newRelease > vault.releaseBlock) {
            vault.releaseBlock = newRelease;
        }
        
        emit RewardAccrued(to, amount, category, newRelease);
    }

    function _verifySignature(
        address merchant, 
        address user, 
        bytes32 packedIntent, 
        uint128 amount, 
        uint256 deadline, 
        uint128 salt, 
        bytes calldata signature
    ) internal view {
        bytes32 hash = _hashTypedDataV4(keccak256(abi.encode(
            EXECUTE_TYPEHASH, 
            merchant, 
            user, 
            packedIntent, 
            amount, 
            deadline, 
            salt, 
            msg.sender
        )));
        
        address signer = config.signerAddress;
        if (signer.code.length > 0) { 
            if (IERC1271(signer).isValidSignature(hash, signature) != 0x1626ba7e) revert Axil__InvalidSignature(); 
        } else { 
            if (hash.recover(signature) != signer) revert Axil__InvalidSignature(); 
        }
    }

    /*//////////////////////////////////////////////////////////////
                                        ADMIN & VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/
    function updateConfig(ConfigKey key, uint256 val, address addr) external onlyRole(ADMIN_ROLE) {
        if (key == ConfigKey.MaxClaim) {
            config.maxClaimLimit = _toU128(val);
        } else if (key == ConfigKey.BatchIter) { 
            if (val > _maxBatchSize()) revert Axil__BatchSizeExceeded(); 
            // forge-lint: disable-next-line(unsafe-typecast)
            config.batchMaxIterations = uint32(val); 
        } else if (key == ConfigKey.Signer) { 
            if (addr == address(0)) revert Axil__ZeroAddressNotAllowed(); 
            config.signerAddress = addr; 
        } else if (key == ConfigKey.Sweep) { 
            if (addr == address(0)) revert Axil__ZeroAddressNotAllowed(); 
            config.sweepReceiver = addr; 
        } else if (key == ConfigKey.BurnLimit) { 
            config.maxBurnQueueLimit = _toU128(val); 
        } else if (key == ConfigKey.UseAllowlist) { 
            // forge-lint: disable-next-line(unsafe-typecast)
            config.useMerchantAllowlist = uint32(val); 
        } else if (key == ConfigKey.BurnCooldown) { 
            // forge-lint: disable-next-line(unsafe-typecast)
            config.burnCooldownActive = uint32(val); 
        } else if (key == ConfigKey.MinExecution) { 
            config.minExecutionAmount = _toU128(val); 
        } else if (key == ConfigKey.MaxRetries) { 
            // forge-lint: disable-next-line(unsafe-typecast)
            config.maxRetryAttempts = uint32(val); 
        }
        emit ConfigUpdated(uint8(key), val, addr);
}

/**
 * @notice Transfer admin role to new address
 * @dev In case of key compromise or ownership transfer
 * @param newAdmin New admin address
 */
  function transferAdmin(address newAdmin) external onlyRole(ADMIN_ROLE) 
  {  if (newAdmin == address(0)) revert Axil__ZeroAddressNotAllowed();
    
    _grantRole(ADMIN_ROLE, newAdmin);
    _revokeRole(ADMIN_ROLE, msg.sender);
    
    emit AdminTransferred(msg.sender, newAdmin);
}

/**
 * @notice Transfer emergency role to new address
 * @dev For emergency backup access
 * @param newEmergency New emergency address
 */
function transferEmergency(address newEmergency) external onlyRole(EMERGENCY_ROLE) {
    if (newEmergency == address(0)) revert Axil__ZeroAddressNotAllowed();
    
    _grantRole(EMERGENCY_ROLE, newEmergency);
    _revokeRole(EMERGENCY_ROLE, msg.sender);
    
    emit EmergencyTransferred(msg.sender, newEmergency);
}

    function sweep(uint256 amount) external onlyRole(TREASURY_ROLE) nonReentrant {
        uint256 reserved = uint256(slotB.totalPendingRewards) + uint256(slotA.failedBurnQueue);
        uint256 available = address(this).balance > reserved ? address(this).balance - reserved : 0;
        if (available == 0) revert Axil__InsufficientContractBalance();
        
        uint256 toSweep = (amount == 0 || amount > available) ? available : amount;
        
        (bool success, ) = payable(config.sweepReceiver).call{value: toSweep}("");
        if (!success) revert Axil__SweepFailed();
        
        emit EmergencySweep(toSweep, config.sweepReceiver);
    }

    function emergencyPause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
        emit EmergencyPaused(msg.sender);
    }

    function emergencyUnpause() external onlyRole(EMERGENCY_ROLE) {
        _unpause();
        emit EmergencyUnpaused(msg.sender);
    }

    function pause() external onlyRole(ADMIN_ROLE) { 
        _pause(); 
    }
    
    function unpause() external onlyRole(ADMIN_ROLE) { 
        _unpause(); 
    }

    function grantMerchantRole(address merchant) external onlyRole(ADMIN_ROLE) {
        if (merchant == address(0)) revert Axil__ZeroAddressNotAllowed();
        _grantRole(MERCHANT_ROLE, merchant);
    }

    function revokeMerchantRole(address merchant) external onlyRole(ADMIN_ROLE) {
        _revokeRole(MERCHANT_ROLE, merchant);
    }


    function version() external pure returns (string memory) {
        return "Axil Protocol V1 - Monad Multiverse Edition"; 
    }
    
    function isIntentExecuted(bytes32 packedIntent) external view returns (bool) { 
        if (intentProcessed[packedIntent]) return true;
        (uint128 bucket, uint128 mask) = unpackIntent(packedIntent);
        return (intentBitmap[bucket] & mask) != 0; 
    }
    
    function getRewardVault(address account) external view returns (uint128 totalAmount, uint64 releaseBlock, uint64 lastClaimed, uint8 retryCount) {
        RewardVault storage vault = pendingRewards[account];
        return (vault.totalAmount, vault.releaseBlock, vault.lastClaimed, vault.retryCount);
    }
    
    function getContractBalance() external view returns (uint256 total, uint256 reserved, uint256 available) {
        total = address(this).balance;
        reserved = uint256(slotB.totalPendingRewards) + uint256(slotA.failedBurnQueue);
        available = total > reserved ? total - reserved : 0;
        return (total, reserved, available);
    }
    
    function getSystemStats() external view returns (
        uint256 totalIntents,
        uint256 totalValue,
        uint256 totalBurnedAmount,
        uint256 pendingRewardsAmount,
        uint256 failedBurnAmount,
        uint64 lastBatchBlock
    ) {
        return (
            totalExecutedIntents,
            totalValueProcessed,
            slotA.totalBurned,
            slotB.totalPendingRewards,
            slotA.failedBurnQueue,
            slotB.lastBatchProcessed
        );
    }

    receive() external payable {}
}