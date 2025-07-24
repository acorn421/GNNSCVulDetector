/*
 * ===== SmartInject Injection Details =====
 * Function      : Divest
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
 * Introduced a timestamp-dependent daily withdrawal limit system that tracks withdrawal amounts and reset times using block.timestamp. The vulnerability creates a multi-transaction exploit where attackers can manipulate miners to adjust block timestamps, allowing them to bypass daily withdrawal limits by triggering premature resets of their withdrawal counters.
 * 
 * **Specific Changes Made:**
 * 1. **State Variables Added**: Added three new state variables to track withdrawal patterns:
 *    - `lastWithdrawTime`: Maps each address to their last withdrawal timestamp
 *    - `dailyWithdrawn`: Maps each address to their total withdrawals in current 24-hour period
 *    - `maxDailyWithdraw`: Sets the maximum daily withdrawal limit (10 ether)
 * 
 * 2. **Timestamp-Based Logic**: Added time-based calculations using `block.timestamp` to determine when the 24-hour period resets, making the contract vulnerable to timestamp manipulation.
 * 
 * 3. **State Persistence**: The vulnerability requires state changes that persist between transactions, specifically the tracking of withdrawal amounts and timestamps.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker makes maximum daily withdrawal (10 ether), setting `lastWithdrawTime[attacker] = block.timestamp` and `dailyWithdrawn[attacker] = 10 ether`
 * 
 * 2. **Between Transactions**: Attacker coordinates with miners or waits for favorable conditions to manipulate `block.timestamp` in subsequent blocks
 * 
 * 3. **Transaction 2**: Attacker calls `Divest()` again in a block where miners have set `block.timestamp` to be `lastWithdrawTime[attacker] + 24 hours` or greater, even though less than 24 hours have actually passed
 * 
 * 4. **Exploitation Result**: The condition `block.timestamp >= lastWithdrawTime[msg.sender] + 24 hours` evaluates to true, resetting `dailyWithdrawn[attacker] = 0` and allowing another 10 ether withdrawal
 * 
 * **Why Multi-Transaction is Required:**
 * - **State Accumulation**: The vulnerability requires previous withdrawal state to be established in earlier transactions
 * - **Time-Based Dependency**: The exploit depends on the relationship between stored timestamps from previous transactions and current block timestamps
 * - **Sequential Exploitation**: Cannot be exploited in a single transaction because it requires the passage of time (or manipulation of time) between withdrawal attempts
 * - **Miner Coordination**: Requires coordination across multiple blocks/transactions to manipulate timestamps effectively
 * 
 * **Realistic Vulnerability Pattern:**
 * This mirrors real-world vulnerabilities where contracts use `block.timestamp` for time-sensitive operations without considering that miners can manipulate timestamps within reasonable bounds (±900 seconds), and sophisticated attackers might coordinate with miners for more significant manipulations.
 */
pragma solidity ^0.4.11;


contract PreSaleFund
{
    address owner = msg.sender;

    event CashMove(uint amount,bytes32 logMsg,address target,address currentOwner);
    
    mapping(address => uint) investors;
    
    uint public MinInvestment = 0.1 ether;
   
    function loggedTransfer(uint amount, bytes32 logMsg, address target, address currentOwner) 
    payable
    {
       if(msg.sender != address(this))throw;
       if(target.call.value(amount)())
       {
          CashMove(amount, logMsg, target, currentOwner);
       }
    }
    
    function Invest() 
    public 
    payable 
    {
        if (msg.value > MinInvestment)
        {
            investors[msg.sender] += msg.value;
        }
    }

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping(address => uint) public lastWithdrawTime;
    mapping(address => uint) public dailyWithdrawn;
    uint public maxDailyWithdraw = 10 ether;
    
    function Divest(uint amount) 
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    public 
    {
        if ( investors[msg.sender] > 0 && amount > 0)
        {
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            // Reset daily withdrawn amount if 24 hours have passed
            if (block.timestamp >= lastWithdrawTime[msg.sender] + 24 hours) {
                dailyWithdrawn[msg.sender] = 0;
            }
            
            // Check if adding this amount would exceed daily limit
            require(dailyWithdrawn[msg.sender] + amount <= maxDailyWithdraw, "Daily withdrawal limit exceeded");
            
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            this.loggedTransfer(amount, "", msg.sender, owner);
            investors[msg.sender] -= amount;
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            
            // Update withdrawal tracking
            dailyWithdrawn[msg.sender] += amount;
            lastWithdrawTime[msg.sender] = block.timestamp;
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        }
    }
    
    function SetMin(uint min)
    public
    {
        if(msg.sender==owner)
        {
            MinInvestment = min;
        }
    }

    function GetInvestedAmount() 
    constant 
    public 
    returns(uint)
    {
        return investors[msg.sender];
    }

    function withdraw() 
    public 
    {
        if(msg.sender==owner)
        {
            this.loggedTransfer(this.balance, "", msg.sender, owner);
        }
    }
    
    
}