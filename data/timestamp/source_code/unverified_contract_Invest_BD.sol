/*
 * ===== SmartInject Injection Details =====
 * Function      : Invest
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by implementing time-based investment bonuses that rely on block.timestamp. The vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Key Changes Made:**
 * 1. **Time-based Early Bird Bonus**: Added a 20% bonus for investments made within the first 7 days using `block.timestamp < (now + 7 days)` - this creates a manipulatable timing window
 * 2. **Flash Bonus System**: Implemented a 10% additional bonus for investments made within the same hour as the last investment using `block.timestamp / 3600 == lastInvestmentHour`
 * 3. **State Persistence**: Added `lastInvestmentHour` tracking and `totalInvestmentsByHour` mapping to maintain timestamp-dependent state between transactions
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Setup Transaction**: Attacker makes initial investment to establish `lastInvestmentHour` state
 * 2. **Timing Manipulation**: Miner/attacker manipulates `block.timestamp` in subsequent blocks to stay within the same hour window
 * 3. **Exploitation Transactions**: Multiple follow-up investments receive the additional 10% flash bonus due to timestamp manipulation
 * 4. **State Accumulation**: Each transaction builds upon the previous state, accumulating bonus benefits that wouldn't be possible in a single transaction
 * 
 * **Why Multi-Transaction is Required:**
 * - The flash bonus system requires a previous investment to set the `lastInvestmentHour` baseline
 * - Miners can manipulate timestamps across multiple blocks but not within a single transaction
 * - The vulnerability becomes more profitable with multiple sequential investments that maintain the hour-based bonus window
 * - State accumulation through `totalInvestmentsByHour` creates persistent effects that enable continued exploitation
 * 
 * **Realistic Attack Vector:**
 * A miner could coordinate multiple investment transactions across consecutive blocks, manipulating `block.timestamp` to maintain the same hour value (timestamp / 3600), receiving the 10% flash bonus on each subsequent investment while appearing to make legitimate sequential investments.
 */
pragma solidity ^0.4.11;

contract PreSaleFund
{
    address owner = msg.sender;

    event CashMove(uint amount,bytes32 logMsg,address target,address currentOwner);
    
    mapping(address => uint) investors;
    
    uint public MinInvestment = 0.1 ether;

    // --- Begin: Added missing variable declarations ---
    uint public lastInvestmentHour;
    mapping(uint => uint) public totalInvestmentsByHour;
    // --- End: Added missing variable declarations ---
   
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
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            // Time-based bonus calculation using block.timestamp
            uint bonusMultiplier = 100; // Base 100% (no bonus)
            
            // Early bird bonus for first 7 days (manipulatable timing window)
            if (block.timestamp < (now + 7 days)) {
                bonusMultiplier = 120; // 20% bonus
            }
            
            // Flash bonus for investments within same hour as last investment
            if (block.timestamp / 3600 == lastInvestmentHour) {
                bonusMultiplier += 10; // Additional 10% bonus
            }
            
            // Calculate investment with time-dependent bonus
            uint investmentAmount = (msg.value * bonusMultiplier) / 100;
            investors[msg.sender] += investmentAmount;
            
            // Update timing state for future bonus calculations
            lastInvestmentHour = block.timestamp / 3600;
            totalInvestmentsByHour[lastInvestmentHour]++;
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
