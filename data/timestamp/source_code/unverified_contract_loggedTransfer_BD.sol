/*
 * ===== SmartInject Injection Details =====
 * Function      : loggedTransfer
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
 * This injection introduces a stateful, multi-transaction timestamp dependence vulnerability by implementing time-based transfer controls that rely on block.timestamp. The vulnerability has two main components:
 * 
 * 1. **Minimum Transfer Interval**: Enforces a 1-hour cooldown between transfers using block.timestamp
 * 2. **Daily Transfer Limits**: Limits transfers to 1 ether per day, resetting at midnight based on block.timestamp
 * 
 * **Specific Changes Made:**
 * - Added state variables to track last transfer time, daily transfer amounts, and reset days
 * - Added MIN_TRANSFER_INTERVAL constant (1 hour) for transfer cooldowns
 * - Added DAILY_TRANSFER_LIMIT constant (1 ether) for daily limits
 * - Added timestamp-based validation logic that uses block.timestamp for all time calculations
 * - Updated state variables after successful transfers
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * This vulnerability requires multiple transactions to exploit because:
 * 
 * 1. **State Accumulation**: The vulnerability depends on accumulated state (daily transfer amounts, last transfer times) that persists between transactions
 * 2. **Time-based Manipulation**: Miners can manipulate block.timestamp within a 15-second window to bypass restrictions across multiple blocks
 * 3. **Sequential Exploitation**: An attacker would need to:
 *    - First transaction: Make a legitimate transfer to establish baseline state
 *    - Subsequent transactions: Coordinate with miners to manipulate timestamps, allowing:
 *      - Bypassing cooldown periods by setting timestamps forward
 *      - Resetting daily limits by jumping to "next day" 
 *      - Making multiple transfers that should be restricted
 * 
 * **Why Multi-Transaction is Required:**
 * - Single transaction cannot manipulate its own timestamp retroactively
 * - The vulnerability requires building up state through legitimate transfers first
 * - Exploitation depends on miners' ability to manipulate timestamps across different blocks
 * - Daily limits and cooldowns only become exploitable when there's existing state to manipulate
 * 
 * **Realistic Attack Vector:**
 * A malicious miner could help an attacker drain funds by manipulating block.timestamp across multiple transactions, effectively bypassing both the hourly cooldown and daily transfer limits, leading to unauthorized fund extraction that should have been prevented by the time-based controls.
 */
pragma solidity ^0.4.11;


contract PreSaleFund
{
    address owner = msg.sender;

    event CashMove(uint amount,bytes32 logMsg,address target,address currentOwner);
    
    mapping(address => uint) investors;
    
    uint public MinInvestment = 0.1 ether;
   
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping(address => uint) public lastTransferTime;
mapping(address => uint) public dailyTransferAmount;
mapping(address => uint) public lastResetDay;
uint public constant DAILY_TRANSFER_LIMIT = 1 ether;
uint public constant MIN_TRANSFER_INTERVAL = 1 hours;

// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
function loggedTransfer(uint amount, bytes32 logMsg, address target, address currentOwner) 
    payable
    {
       if(msg.sender != address(this))throw;
       // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
       
       // Reset daily transfer amount if it's a new day
       uint currentDay = block.timestamp / 86400; // 86400 seconds in a day
       if(currentDay > lastResetDay[target]) {
           dailyTransferAmount[target] = 0;
           lastResetDay[target] = currentDay;
       }
       
       // Check minimum interval between transfers (vulnerable to timestamp manipulation)
       if(block.timestamp < lastTransferTime[target] + MIN_TRANSFER_INTERVAL) {
           throw;
       }
       
       // Check daily transfer limit (vulnerable to timestamp manipulation)
       if(dailyTransferAmount[target] + amount > DAILY_TRANSFER_LIMIT) {
           throw;
       }
       
       // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
       if(target.call.value(amount)())
       {
          // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
          // Update state variables with current block timestamp
          lastTransferTime[target] = block.timestamp;
          dailyTransferAmount[target] += amount;
          
          // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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

    function Divest(uint amount) 
    public 
    {
        if ( investors[msg.sender] > 0 && amount > 0)
        {
            this.loggedTransfer(amount, "", msg.sender, owner);
            investors[msg.sender] -= amount;
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