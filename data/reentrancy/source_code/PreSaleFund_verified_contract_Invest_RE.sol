/*
 * ===== SmartInject Injection Details =====
 * Function      : Invest
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call After State Update**: Introduced a call to `msg.sender.call()` that invokes an `onInvestmentReceived` callback on the investor's address (if it's a contract)
 * 2. **Maintained State Update Pattern**: The `investors[msg.sender] += msg.value` still happens first, but the external call occurs before the function completes
 * 3. **Realistic Justification**: The external call is framed as a notification system for investment tracking, which is a common legitimate pattern in DeFi protocols
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1: Initial Investment Setup**
 * - Attacker deploys a malicious contract with `onInvestmentReceived` callback
 * - Makes initial investment through malicious contract to establish state in `investors` mapping
 * - This transaction succeeds normally and establishes the attacker's balance
 * 
 * **Transaction 2: Reentrancy Attack**
 * - Attacker makes another investment call through the malicious contract
 * - When `Invest()` updates `investors[msg.sender] += msg.value`, the state is temporarily inconsistent
 * - The external call triggers the attacker's `onInvestmentReceived` callback
 * - Within the callback, the attacker can call `Divest()` or other functions that depend on the `investors` mapping
 * - Since the original `Invest()` transaction hasn't completed, the attacker can exploit the intermediate state
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * 
 * 1. **State Accumulation Dependency**: The vulnerability becomes more severe as the attacker accumulates larger balances over multiple investments, making the potential damage from reentrancy attacks more significant
 * 
 * 2. **Contract Deployment Prerequisite**: The attacker must first deploy a malicious contract with the callback function in a separate transaction before they can exploit the reentrancy
 * 
 * 3. **Investment History Requirement**: The external call only triggers when `investors[msg.sender] > 0`, requiring at least one previous successful investment to establish the attack vector
 * 
 * 4. **Increased Attack Surface**: Multiple investments build up the attacker's balance, creating larger potential drainage amounts during reentrancy attacks on functions like `Divest()`
 * 
 * **Exploitation Flow:**
 * 1. **Setup Phase** (Transaction 1): Deploy malicious contract, make initial investment
 * 2. **Accumulation Phase** (Transactions 2-N): Build up investment balance over multiple calls
 * 3. **Attack Phase** (Transaction N+1): Trigger reentrancy through accumulated state, potentially draining contract through `Divest()` calls during the callback
 * 
 * The vulnerability is stateful because it depends on the persistent `investors` mapping state and requires multiple transactions to establish the attack prerequisites and maximize the exploitation impact.
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
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Notify external investment tracker about the new investment
            if (investors[msg.sender] > 0) {
                // External call before final state consistency check
                msg.sender.call(bytes4(keccak256("onInvestmentReceived(uint256,uint256)")), 
                               msg.value, investors[msg.sender]);
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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