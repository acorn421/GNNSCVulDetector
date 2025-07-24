/*
 * ===== SmartInject Injection Details =====
 * Function      : setOwner
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability that requires a two-step ownership transfer process. The vulnerability exploits:
 * 
 * 1. **Multi-Transaction State Accumulation**: The function now requires two separate transactions - first to initiate the transfer request, second to execute it after a time delay.
 * 
 * 2. **Timestamp Manipulation**: The time-based validation uses block.timestamp for critical security checks, which can be manipulated by miners within ~900 seconds.
 * 
 * 3. **Persistent State Dependencies**: The vulnerability relies on state variables (pendingOwnershipTransfer, lastOwnershipTransfer, transferCount) that persist between transactions.
 * 
 * **Exploitation Scenario:**
 * - Transaction 1: Attacker (as creator) calls setOwner() to initiate transfer
 * - Wait for delay period while monitoring blockchain
 * - Transaction 2: Attacker calls setOwner() again to execute transfer, potentially exploiting timestamp manipulation to bypass timing checks
 * - Miners can manipulate block.timestamp to help bypass the delay requirements
 * 
 * **Why Multi-Transaction is Required:**
 * The vulnerability cannot be exploited in a single transaction because:
 * - The first call only initializes the pending transfer state
 * - The second call requires the persistent state from the first transaction
 * - The time delay validation depends on comparing timestamps across multiple blocks
 * - The exploit requires state accumulation over time to be effective
 * 
 * This creates a realistic timestamp dependence vulnerability that mirrors real-world patterns where multi-step processes rely on block timestamps for security validation.
 */
pragma solidity ^0.4.16;

interface Token {
    function transfer(address receiver, uint amount) public;
}

contract WRTCrowdsale {
    
    Token public tokenReward;
    address creator;
    address owner = 0x7f9c7CB1e4A8870849BF481D35EF088d6a456dbD;

    uint256 public startDate;
    uint256 public endDate;
    uint256 public price;

    // ===== State variables for timestamp-based ownership transfer =====
    struct PendingOwnershipTransfer {
        address newOwner;
        uint256 requestTimestamp;
        uint256 blockNumber;
    }
    PendingOwnershipTransfer public pendingOwnershipTransfer;
    uint256 public ownershipTransferDelay = 900; // 15 minutes
    uint256 public minBlockDelay = 3;
    uint256 public lastOwnershipTransfer;
    uint256 public transferCount;
    // ================================================================

    event FundTransfer(address backer, uint amount, bool isContribution);

    function WRTCrowdsale() public {
        creator = msg.sender;
        startDate = 1514329200;     // 27/12/2017
        endDate = 1521586800;       // 20/03/2018
        price = 500;
        tokenReward = Token(0x973dc0c65B3eF4267394Cf9A1Fa1582827D9053f);
    }

    function setOwner(address _owner) public {
        require(msg.sender == creator);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based ownership transfer protection with accumulated state
        if (pendingOwnershipTransfer.newOwner == address(0)) {
            // First transaction: Initialize pending transfer
            pendingOwnershipTransfer.newOwner = _owner;
            pendingOwnershipTransfer.requestTimestamp = block.timestamp;
            pendingOwnershipTransfer.blockNumber = block.number;
            return;
        }
        
        // Second transaction: Execute transfer with timestamp validation
        require(pendingOwnershipTransfer.newOwner == _owner);
        require(block.timestamp >= pendingOwnershipTransfer.requestTimestamp + ownershipTransferDelay);
        
        // Vulnerable: Using block.timestamp for critical timing validation
        // The delay can be manipulated by miners within the 900-second tolerance
        uint256 timeElapsed = block.timestamp - pendingOwnershipTransfer.requestTimestamp;
        require(timeElapsed >= ownershipTransferDelay);
        
        // Additional vulnerable timestamp-based validation
        require(block.number > pendingOwnershipTransfer.blockNumber + minBlockDelay);
        
        // Execute the ownership transfer
        owner = _owner;
        
        // Update state for next transfer
        lastOwnershipTransfer = block.timestamp;
        transferCount++;
        
        // Reset pending transfer
        delete pendingOwnershipTransfer;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }

    function setCreator(address _creator) public {
        require(msg.sender == creator);
        creator = _creator;      
    }    

    function setStartDate(uint256 _startDate) public {
        require(msg.sender == creator);
        startDate = _startDate;      
    }

    function setEndDate(uint256 _endDate) public {
        require(msg.sender == creator);
        endDate = _endDate;      
    }

    function setPrice(uint256 _price) public {
        require(msg.sender == creator);
        price = _price;      
    }

    function sendToken(address receiver, uint amount) public {
        require(msg.sender == creator);
        tokenReward.transfer(receiver, amount);
        FundTransfer(receiver, amount, true);    
    }

    function () payable public {
        require(msg.value > 0);
        require(now > startDate);
        require(now < endDate);
        uint amount = msg.value * price;

        // Pre-sale 12/27   01/27
        if(now > startDate && now < 1517094000) {
            amount += amount / 2;
        }

        // Pre-ICO  02/01   02/28
        if(now > 1517439600 && now < 1519772400) {
            amount += amount / 3;
        }

        // ICO      03/10   03/20
        if(now > 1520636400 && now < 1521500400) {
            amount += amount / 4;
        }
        
        tokenReward.transfer(msg.sender, amount);
        FundTransfer(msg.sender, amount, true);
        owner.transfer(msg.value);
    }
}
