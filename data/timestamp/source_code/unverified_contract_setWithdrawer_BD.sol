/*
 * ===== SmartInject Injection Details =====
 * Function      : setWithdrawer
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through a time-locked withdrawer change system. The vulnerability requires multiple state variables (withdrawerChangeTime, pendingWithdrawer, pendingWithdrawerTime) and creates several exploit vectors:
 * 
 * 1. **Multi-Transaction Exploitation Path**: For non-owner addresses, the function requires two separate transactions spaced 30 minutes apart to complete the withdrawer change. This creates a stateful vulnerability where the first transaction sets up the pending state, and the second transaction (after timestamp validation) completes the change.
 * 
 * 2. **Timestamp Manipulation Vulnerability**: Miners can manipulate block.timestamp within a ~15-second window to bypass time restrictions. Since the vulnerability spans multiple blocks, miners can:
 *    - Accelerate the pending confirmation period by setting future timestamps
 *    - Coordinate timestamp manipulation across multiple blocks to bypass the 1-hour cooldown
 *    - Create race conditions where legitimate users think they have more time than they actually do
 * 
 * 3. **State Accumulation Requirement**: The vulnerability requires persistent state changes across transactions:
 *    - First transaction: Sets pendingWithdrawer and pendingWithdrawerTime
 *    - Second transaction: Validates timing and completes the withdrawer change
 *    - The withdrawerChangeTime state persists to enforce cooldown periods
 * 
 * 4. **Attack Scenarios**:
 *    - **Scenario 1**: Malicious owner initiates withdrawer change, then manipulates timestamps across blocks to bypass waiting periods
 *    - **Scenario 2**: Attacker gains temporary owner access, uses timestamp manipulation to rapidly change withdrawer multiple times
 *    - **Scenario 3**: Front-running attacks where attackers monitor pending withdrawer changes and exploit timestamp dependencies
 * 
 * The vulnerability is realistic because it implements seemingly reasonable security measures (cooldowns, multi-step confirmations) but relies on manipulable timestamp values for critical security logic. The multi-transaction nature makes it more dangerous as it can persist across blocks and be exploited through miner collaboration or timestamp manipulation techniques.
 */
pragma solidity ^0.4.24;

contract Bank {
    string public name = "bank";
    address public owner;
    address public withdrawer;
    uint256 public withdrawerChangeTime;
    address public pendingWithdrawer;
    uint256 public pendingWithdrawerTime;

    constructor()
        public
    {
        owner = msg.sender;
    }

    function()
        public
        payable
    {
        // do nothing
    }

    function deposit(address _addr)
        external
        payable
        returns (bool)
    {
        require(msg.value > 0, "Failed - zero deposits not allowed");
        return (true);
    }

    function migrationReceiver_setup()
        external
        returns (bool)
    {
        return (true);
    }

    function setWithdrawer(address _withdrawer)
        public
        returns (bool)
    {
        require(msg.sender == owner);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-locked withdrawer changes with cooldown period
        if (withdrawerChangeTime != 0) {
            require(block.timestamp >= withdrawerChangeTime + 1 hours, "Withdrawer change cooldown active");
        }
        
        // Store the current timestamp for next change cooldown
        withdrawerChangeTime = block.timestamp;
        
        // Progressive security: require multiple confirmations over time for critical addresses
        if (_withdrawer != address(0) && _withdrawer != owner) {
            if (pendingWithdrawer == _withdrawer) {
                // Second confirmation - check if enough time has passed
                require(block.timestamp >= pendingWithdrawerTime + 30 minutes, "Insufficient time between confirmations");
                withdrawer = _withdrawer;
                pendingWithdrawer = address(0);
                pendingWithdrawerTime = 0;
            } else {
                // First confirmation - store as pending
                pendingWithdrawer = _withdrawer;
                pendingWithdrawerTime = block.timestamp;
            }
        } else {
            // Owner or zero address can be set immediately
            withdrawer = _withdrawer;
            pendingWithdrawer = address(0);
            pendingWithdrawerTime = 0;
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

        return (true);
    }

    function withdraw()
        public
        returns (bool)
    {
        require(msg.sender == withdrawer);
        withdrawer.transfer(address(this).balance);

        return (true);
    }

    function getContractBalance()
        public
        view
        returns (uint)
    {
        return (address(this).balance);
    }
}
