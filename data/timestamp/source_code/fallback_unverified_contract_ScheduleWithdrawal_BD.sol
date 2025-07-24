/*
 * ===== SmartInject Injection Details =====
 * Function      : ScheduleWithdrawal
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence through a multi-transaction withdrawal scheduling system. The vulnerability is stateful and requires multiple transactions: 1) First, an investor must call ScheduleWithdrawal() to schedule a withdrawal with a timestamp-based delay. 2) Then, they must wait for the delay period and call ExecuteScheduledWithdrawal() to complete the withdrawal. The vulnerability lies in the reliance on 'now' (block.timestamp) for timing controls, which can be manipulated by miners within certain bounds (~900 seconds). A malicious miner could manipulate timestamps to either delay legitimate withdrawals or accelerate their own scheduled withdrawals. The state persists between transactions through the withdrawalSchedule mapping, making this a true multi-transaction stateful vulnerability.
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
    
    

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    mapping(address => uint) public withdrawalSchedule;
    uint public withdrawalDelay = 1 days;
    
    function ScheduleWithdrawal(uint amount) 
    public 
    {
        if (investors[msg.sender] >= amount && amount > 0) {
            withdrawalSchedule[msg.sender] = now + withdrawalDelay;
        }
    }
    
    function ExecuteScheduledWithdrawal(uint amount) 
    public 
    {
        if (withdrawalSchedule[msg.sender] != 0 && 
            now >= withdrawalSchedule[msg.sender] && 
            investors[msg.sender] >= amount) {
            
            withdrawalSchedule[msg.sender] = 0;
            this.loggedTransfer(amount, "scheduled_withdrawal", msg.sender, owner);
            investors[msg.sender] -= amount;
        }
    }
    
    function UpdateWithdrawalDelay(uint newDelay) 
    public 
    {
        if (msg.sender == owner) {
            withdrawalDelay = newDelay;
        }
    }
    // === END FALLBACK INJECTION ===

}