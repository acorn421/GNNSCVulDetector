/*
 * ===== SmartInject Injection Details =====
 * Function      : loggedTransfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful multi-transaction reentrancy vulnerability by adding persistent state variables (transferCount and pendingTransfers mapping) that accumulate across multiple transactions. The vulnerability requires at least 3 function calls to trigger the exploitable condition, and the state cleanup occurs after the external call, creating a window where an attacker can reenter and manipulate the accumulated state. The exploit works by: 1) Making 2 initial calls to build up transferCount and pendingTransfers state, 2) On the 3rd call, the condition is met and external call is made, 3) During reentrancy, the attacker can manipulate pendingTransfers before state cleanup occurs, 4) Multiple reentrant calls can drain funds by exploiting the accumulated state that persists between the external call and state reset.
 */
pragma solidity ^0.4.11;

contract PreSaleFund
{
    address owner = msg.sender;

    event CashMove(uint amount,bytes32 logMsg,address target,address currentOwner);
    
    mapping(address => uint) investors;
    
    uint public MinInvestment = 0.1 ether;

    // Added declarations to fix compilation errors
    uint transferCount;
    mapping(address => uint) pendingTransfers;
   
    function loggedTransfer(uint amount, bytes32 logMsg, address target, address currentOwner) 
    payable
    {
       if(msg.sender != address(this)) throw;
       // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
       // State tracking for multi-transaction vulnerability
       transferCount++;
       pendingTransfers[target] += amount;
       // Vulnerable pattern: external call before state finalization
       // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
       if(target.call.value(amount)())
       {
          CashMove(amount, logMsg, target, currentOwner);
          // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
          // Critical vulnerability: state cleanup only after successful call
          // but reentrancy can manipulate pendingTransfers before this point
          if(transferCount >= 3 && pendingTransfers[target] > 0.5 ether) {
             // Accumulated state creates vulnerability window
             pendingTransfers[target] = 0; // State reset after external call
             transferCount = 0;
          }
          // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
