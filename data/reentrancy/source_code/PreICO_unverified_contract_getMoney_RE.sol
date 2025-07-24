/*
 * ===== SmartInject Injection Details =====
 * Function      : getMoney
 * Vulnerability : Reentrancy
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a daily withdrawal limit system with state tracking. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added state variables to track withdrawal limits, amounts withdrawn today, and last withdrawal times
 * 2. Implemented a daily withdrawal limit of 1 ETH with a 24-hour cooldown period
 * 3. Moved state updates (managerWithdrawnToday and lastWithdrawalTime) to occur AFTER the external call to manager.send()
 * 4. Added logic to reset daily withdrawal amounts after cooldown period
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: Manager calls getMoney() legitimately, withdraws up to daily limit
 * 2. **Transaction 2**: Manager deploys a malicious contract that acts as the manager address
 * 3. **Transaction 3**: Malicious contract calls getMoney(), and during the send() callback, immediately calls getMoney() again before state is updated
 * 4. **Subsequent Transactions**: The attacker can repeatedly exploit the window between external call and state update across multiple transactions
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability requires establishing withdrawal history state in initial transactions
 * - The daily limit system only becomes exploitable after legitimate usage patterns are established
 * - The attacker needs separate transactions to set up the malicious contract and execute the reentrancy attack
 * - Each reentrancy exploitation requires the state to be in a specific condition that can only be achieved through previous transactions
 * 
 * **State Persistence Vulnerability:**
 * The state variables (managerWithdrawnToday, lastWithdrawalTime) persist between transactions, creating a window where the attacker can exploit the inconsistent state across multiple function calls, allowing them to bypass the daily withdrawal limits through carefully timed reentrancy attacks.
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

    function PreICO(){
        manager = msg.sender;
        isPreIco = false;
    }

    modifier isManager(){
        if (msg.sender!=manager) throw;
        _;
    }

    function kill() isManager {
        suicide(manager);
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint256) private managerWithdrawalLimits;
    mapping(address => uint256) private managerWithdrawnToday;
    mapping(address => uint256) private lastWithdrawalTime;
    uint256 private constant DAILY_WITHDRAWAL_LIMIT = 1000000000000000000; // 1 ETH
    uint256 private constant WITHDRAWAL_COOLDOWN = 86400; // 24 hours

    function getMoney() isManager {
        // Initialize withdrawal limits for new managers
        if(managerWithdrawalLimits[msg.sender] == 0) {
            managerWithdrawalLimits[msg.sender] = DAILY_WITHDRAWAL_LIMIT;
        }
        
        // Reset daily withdrawal if cooldown period has passed
        if(block.timestamp >= lastWithdrawalTime[msg.sender] + WITHDRAWAL_COOLDOWN) {
            managerWithdrawnToday[msg.sender] = 0;
        }
        
        // Calculate available withdrawal amount
        uint256 availableAmount = managerWithdrawalLimits[msg.sender] - managerWithdrawnToday[msg.sender];
        uint256 withdrawalAmount = (this.balance < availableAmount) ? this.balance : availableAmount;
        
        require(withdrawalAmount > 0, "No funds available for withdrawal");
        
        // VULNERABILITY: External call before state update
        if(manager.send(withdrawalAmount) == false) throw;
        
        // State updates after external call - vulnerable to reentrancy
        managerWithdrawnToday[msg.sender] += withdrawalAmount;
        lastWithdrawalTime[msg.sender] = block.timestamp;
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function startPreICO() isManager {
        isPreIco = true;
    }

    function stopPreICO() isManager {
        isPreIco = false;
    }

    function countHolders() constant returns(uint256){
        return listHolders.length;
    }

    function getItemHolder(uint256 index) constant returns(address){
        if(index >= listHolders.length || listHolders.length == 0) return address(0x0);
        return listHolders[index];
    }

    function balancsHolder(address who) constant returns(uint256){
        return holders[who].balance;
    }

    function() payable
    {
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