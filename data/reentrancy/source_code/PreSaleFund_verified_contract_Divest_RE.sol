/*
 * ===== SmartInject Injection Details =====
 * Function      : Divest
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by creating a complex state management pattern that appears to prevent reentrancy but actually enables it across multiple transactions. The vulnerability works as follows:
 * 
 * **Multi-Transaction Exploitation Sequence:**
 * 
 * 1. **Transaction 1 (Setup)**: Attacker calls Divest() with amount less than their balance
 *    - Function temporarily sets investors[attacker] = 0 to prevent simple reentrancy
 *    - External call to loggedTransfer() is made, which can trigger reentrancy
 *    - After external call, remaining balance is restored to investors[attacker]
 * 
 * 2. **Transaction 2+ (Exploitation)**: During the external call in Transaction 1, attacker can:
 *    - Call Divest() again through reentrancy
 *    - Since investors[attacker] was temporarily set to 0, the check passes with stored withdrawalAllowance
 *    - This allows draining more funds than originally invested across multiple reentrant calls
 * 
 * **Why Multi-Transaction Dependency is Critical:**
 * 
 * - The vulnerability requires the initial state setup (investor balance > 0) from previous Invest() transactions
 * - The exploit depends on the temporary state manipulation within the function call
 * - Multiple reentrant calls are needed to drain funds exceeding the original investment
 * - The state restoration after external call creates a window for accumulated exploitation
 * 
 * **Realistic Vulnerability Pattern:**
 * 
 * This represents a realistic attempt to fix reentrancy that actually introduces a more complex vulnerability - developers might think temporarily zeroing the balance prevents reentrancy, but the state restoration creates the exploit opportunity. The multi-transaction nature makes it harder to detect and more dangerous in practice.
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
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Add partial state update before external call to create withdrawal allowance
            uint withdrawalAllowance = investors[msg.sender];
            investors[msg.sender] = 0; // Temporarily zero out to prevent simple reentrancy
            
            this.loggedTransfer(amount, "", msg.sender, owner);
            
            // Restore remaining balance after external call - this creates the vulnerability
            if (withdrawalAllowance > amount) {
                investors[msg.sender] = withdrawalAllowance - amount;
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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