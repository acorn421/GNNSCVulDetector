/*
 * ===== SmartInject Injection Details =====
 * Function      : setCreator
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction timestamp dependence vulnerability by implementing a time-locked creator change mechanism. The vulnerability requires multiple transactions and exploits miners' ability to manipulate block timestamps.
 * 
 * **State Variables Added (assumed to exist in contract):**
 * - `address pendingCreator` - stores the pending new creator address
 * - `uint256 pendingCreatorTimestamp` - stores when the creator change was initiated
 * 
 * **Specific Changes Made:**
 * 
 * 1. **Time-Locked Creator Changes**: The function now implements a 24-hour cooldown period where creator changes must wait before becoming effective.
 * 
 * 2. **Multi-Transaction Requirement**: 
 *    - First transaction: Sets pendingCreator and pendingCreatorTimestamp
 *    - Second transaction: After 24 hours, finalizes the creator change
 * 
 * 3. **Timestamp Dependence**: Uses `block.timestamp` for critical time-based logic without proper validation
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Initiation):**
 * - Attacker calls `setCreator(attackerAddress)` 
 * - Function sets `pendingCreator = attackerAddress` and `pendingCreatorTimestamp = block.timestamp`
 * - No immediate creator change occurs
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker waits for 24 hours OR collaborates with a miner to manipulate timestamps
 * - Miner can set `block.timestamp` to be >= `pendingCreatorTimestamp + 86400` even if real time hasn't passed
 * - Attacker calls `setCreator(attackerAddress)` again
 * - Function checks `block.timestamp >= pendingCreatorTimestamp + 86400` (vulnerable timestamp check)
 * - Creator change is finalized, giving attacker control
 * 
 * **Why Multi-Transaction is Required:**
 * - Single transaction cannot exploit this because the initial state (pendingCreatorTimestamp = 0) requires setup
 * - State must persist between transactions to track the pending change and timing
 * - The vulnerability relies on accumulated state changes across multiple blocks/transactions
 * - Even with timestamp manipulation, two separate transactions are needed to first set the pending state, then exploit the timing check
 * 
 * **Real-World Impact:**
 * - Miners could manipulate timestamps to bypass the 24-hour security delay
 * - Attackers could gain premature access to creator privileges
 * - Time-based security controls become ineffective against miner collusion
 */
pragma solidity ^0.4.16;

interface Token {
    function transfer(address _to, uint256 _value) external;
}

contract ETHLCrowdsale {
    
    Token public tokenReward;
    address public creator;
    address public owner = 0x0;

    uint256 private tokenSold;
    
    // Added missing storage for pendingCreator logic
    address public pendingCreator = address(0);
    uint256 public pendingCreatorTimestamp = 0;

    modifier isCreator() {
        require(msg.sender == creator);
        _;
    }

    event FundTransfer(address backer, uint amount, bool isContribution);

    // Updated constructor syntax for >=0.4.22 warning; okay for 0.4.16, but removed warning in newer
    function ETHLCrowdsale() public {
        creator = msg.sender;
        tokenReward = Token(0x813a823F35132D822708124e01759C565AB4331d);
    }

    function setOwner(address _owner) isCreator public {
        owner = _owner;      
    }

    function setCreator(address _creator) isCreator public {
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Initialize pendingCreator storage if not set
        if (pendingCreatorTimestamp == 0) {
            pendingCreator = _creator;
            pendingCreatorTimestamp = block.timestamp;
            return;
        }
        
        // Check if enough time has passed (24 hours = 86400 seconds)
        if (block.timestamp >= pendingCreatorTimestamp + 86400) {
            // Time window passed, apply the pending creator change
            creator = pendingCreator;
            pendingCreator = address(0);
            pendingCreatorTimestamp = 0;
        } else {
            // Not enough time passed, update pending creator and reset timer
            pendingCreator = _creator;
            pendingCreatorTimestamp = block.timestamp;
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }

    function setToken(address _token) isCreator public {
        tokenReward = Token(_token);      
    }

    function sendToken(address _to, uint256 _value) isCreator public {
        tokenReward.transfer(_to, _value);      
    }

    function kill() isCreator public {
        selfdestruct(owner);
    }

    function () payable public {
        require(msg.value > 0);
        uint256 amount;
        
        // stage 1
        if (now > 1525129200 && now < 1525734000 && tokenSold < 350001) {
            amount = msg.value * 2500;
        }

        // stage 2
        if (now > 1525733999 && now < 1526252400 && tokenSold > 350000 && tokenSold < 700001) {
            amount = msg.value * 1250;
        }

        // stage 3
        if (now > 1526252399 && now < 1526857200 && tokenSold > 700000 && tokenSold < 1150001) {
            amount = msg.value * 833;
        }

        // stage 4
        if (now > 1526857199 && now < 1527721200 && tokenSold > 1150000 && tokenSold < 2000001) {
            amount = msg.value * 416;
        }

        // stage 5
        if (now > 1527721199 && now < 1528671600 && tokenSold > 2000000 && tokenSold < 3000001) {
            amount = msg.value * 357;
        }

        // stage 6
        if (now > 1528671599 && now < 1530399600 && tokenSold > 3000000 && tokenSold < 4000001) {
            amount = msg.value * 333;
        }

        tokenSold += amount / 1 ether;
        tokenReward.transfer(msg.sender, amount);
        FundTransfer(msg.sender, amount, true);
        owner.transfer(msg.value);
    }
}
