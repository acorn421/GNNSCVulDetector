/*
 * ===== SmartInject Injection Details =====
 * Function      : stopPreICO
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
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability by implementing a cooldown mechanism that relies on block.timestamp for critical timing decisions. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **State Variables Added** (assumed to be added to contract):
 *    - `uint256 lastStateChangeTime` - tracks when PreICO state was last changed
 *    - `uint256 pendingStopTime` - stores timestamp of pending stop requests
 * 
 * 2. **Multi-Transaction Exploitation Path**:
 *    - Transaction 1: Call startPreICO() to set lastStateChangeTime
 *    - Transaction 2: Call stopPreICO() within cooldown period - creates pending stop request
 *    - Transaction 3: Call stopPreICO() again after grace period - actually stops PreICO
 *    - Miners can manipulate block.timestamp between these transactions
 * 
 * 3. **Vulnerability Mechanics**:
 *    - The function uses block.timestamp for critical timing decisions
 *    - Miners can manipulate block.timestamp within ~15 minutes of real time
 *    - The cooldown and grace period create windows for timestamp manipulation
 *    - Attackers with mining power can coordinate timing to bypass intended restrictions
 * 
 * 4. **Realistic Attack Scenarios**:
 *    - Malicious miners can set favorable timestamps to prematurely stop PreICO
 *    - Coordinated attacks across multiple blocks to exploit timing windows
 *    - Sequential exploitation where timing manipulation affects multiple transactions
 * 
 * The vulnerability maintains the original function's purpose while introducing a genuine security flaw that requires multiple transactions and state persistence to exploit effectively.
 */
pragma solidity ^0.4.8;

contract PreICO {
    bool public isPreIco;
    address manager;

    uint256 maxPreOrderAmount = 500000000000000000000; //in wei
    uint256 maxAmountSupply = 1875000000000000000000;

    struct dataHolder {
        uint256 balance;
        bool init;
    }
    mapping(address => dataHolder) holders;
    address[] listHolders;

    // Added state variables needed for stopPreICO
    uint256 public lastStateChangeTime;
    uint256 public pendingStopTime;

    function PreICO() public {
        manager = msg.sender;
        isPreIco = false;
        lastStateChangeTime = 0;
        pendingStopTime = 0;
    }

    modifier isManager() {
        if (msg.sender != manager) throw;
        _;
    }

    function kill() isManager {
        suicide(manager);
    }

    function getMoney() isManager {
        if(manager.send(this.balance) == false) throw;
    }

    function startPreICO() isManager {
        isPreIco = true;
        lastStateChangeTime = block.timestamp;
    }

    function stopPreICO() isManager {
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Add timestamp-based cooldown period before PreICO can be stopped
        uint256 cooldownPeriod = 300; // 5 minutes in seconds
        
        // Check if enough time has passed since last state change
        if (block.timestamp < lastStateChangeTime + cooldownPeriod) {
            // Store the stop request timestamp for later processing
            pendingStopTime = block.timestamp;
            return;
        }
        
        // If there's a pending stop request, check if it's from a favorable timestamp
        if (pendingStopTime > 0) {
            // Vulnerable: Using block.timestamp for critical timing decisions
            // Miners can manipulate this timestamp within ~900 seconds
            if (block.timestamp >= pendingStopTime + 60) { // 1 minute grace period
                isPreIco = false;
                lastStateChangeTime = block.timestamp;
                pendingStopTime = 0;
            }
        } else {
            // Direct stop if no cooldown restriction
            isPreIco = false;
            lastStateChangeTime = block.timestamp;
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }

    function countHolders() constant returns(uint256) {
        return listHolders.length;
    }

    function getItemHolder(uint256 index) constant returns(address) {
        if(index >= listHolders.length || listHolders.length == 0) return address(0x0);
        return listHolders[index];
    }

    function balancsHolder(address who) constant returns(uint256) {
        return holders[who].balance;
    }

    function() payable {
        if(isPreIco == false) throw;

        uint256 amount = msg.value;

        uint256 return_amount = 0;

        if(this.balance + msg.value > maxAmountSupply){
            amount = maxAmountSupply - this.balance ;
            return_amount = msg.value - amount;
        }

        if(holders[msg.sender].init == false){
            listHolders.push(msg.sender);
            holders[msg.sender].init = true;
        }

        if((amount+holders[msg.sender].balance) > maxPreOrderAmount){
            return_amount += ((amount+holders[msg.sender].balance) - maxPreOrderAmount);
            holders[msg.sender].balance = maxPreOrderAmount;
        }
        else{
            holders[msg.sender].balance += amount;
        }

        if(return_amount>0){
            if(msg.sender.send(return_amount)==false) throw;
        }

        if(this.balance == maxAmountSupply){
            isPreIco = false;
        }
    }
}
