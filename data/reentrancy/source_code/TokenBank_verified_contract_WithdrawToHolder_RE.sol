/*
 * ===== SmartInject Injection Details =====
 * Function      : WithdrawToHolder
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
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **State Tracking Enhancement**: Added `previousBalance` variable to track the holder's balance before withdrawal, creating a more complex state management pattern that enables multi-transaction exploitation.
 * 
 * 2. **Extended Vulnerability Window**: Wrapped the external call in a conditional check that only updates state after successful execution, creating a longer window where the contract state remains inconsistent during reentrancy.
 * 
 * 3. **Multi-Transaction Exploitation Path**: 
 *    - **Transaction 1**: Attacker calls WithdrawToHolder to initiate withdrawal
 *    - **During External Call**: The receiving contract can re-enter WithdrawToHolder while the original transaction is still executing
 *    - **Transaction 2+**: Multiple nested calls can occur before the original state update completes
 *    - **State Persistence**: The `Holders` mapping maintains state between these nested calls, allowing cumulative exploitation
 * 
 * 4. **Why Multi-Transaction is Required**:
 *    - The vulnerability relies on the persistent state in the `Holders` mapping across multiple function calls
 *    - Each reentrancy call checks the same `Holders[_addr]` balance that hasn't been updated yet
 *    - The attacker needs to set up initial conditions (having balance in Holders) in separate transactions before exploitation
 *    - The exploitation pattern requires multiple nested calls to drain funds incrementally
 * 
 * 5. **Realistic Vulnerability Pattern**: This modification maintains the original function's intended behavior while introducing a subtle but exploitable reentrancy vulnerability that requires multiple transactions to be effectively exploited, making it suitable for security research datasets.
 */
pragma solidity ^0.4.18;

contract Ownable
{
    address newOwner;
    address owner;
    
    function Ownable() public {
        owner = msg.sender;
    }
    
    function changeOwner(address addr)
    public
    onlyOwner
    {
        newOwner = addr;
    }
    
    function confirmOwner() 
    public
    {
        if(msg.sender==newOwner)
        {
            owner=newOwner;
        }
    }
    
    modifier onlyOwner
    {
        if(owner == msg.sender) _;
    }
}

contract Token is Ownable
{
    function WithdrawToken(address token, uint256 amount,address to)
    public 
    onlyOwner
    {
        token.call(bytes4(keccak256("transfer(address,uint256)")),to,amount); 
    }
}

contract TokenBank is Token
{
    uint public MinDeposit;
    mapping (address => uint) public Holders;
    
     ///Constructor
    function initTokenBank()
    public
    {
        owner = msg.sender;
        MinDeposit = 1 ether;
    }
    
    function() public payable
    {
        Deposit();
    }
   
    function Deposit() 
    public
    payable
    {
        if(msg.value>MinDeposit)
        {
            Holders[msg.sender]+=msg.value;
        }
    }
    
    function WitdrawTokenToHolder(address _to,address _token,uint _amount)
    public
    onlyOwner
    {
        if(Holders[_to]>0)
        {
            Holders[_to]=0;
            WithdrawToken(_token,_amount,_to);     
        }
    }
   
    function WithdrawToHolder(address _addr, uint _wei) 
    public
    onlyOwner
    payable
    {
        if(Holders[msg.sender]>0)
        {
            if(Holders[_addr]>=_wei)
            {
                // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                // Add withdrawal tracking to enable multi-transaction exploitation
                uint previousBalance = Holders[_addr];
                
                // External call before state update - enables reentrancy
                if(_addr.call.value(_wei)())
                {
                    // Only update state after successful call
                    // This creates a window for multi-transaction reentrancy
                    Holders[_addr] = previousBalance - _wei;
                }
                else
                {
                    // On failure, restore state but with vulnerability window
                    Holders[_addr] = previousBalance;
                }
                // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            }
        }
    }
    
    function Bal() public constant returns(uint){return address(this).balance;}
}
