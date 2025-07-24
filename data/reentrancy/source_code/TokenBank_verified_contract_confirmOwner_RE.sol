/*
 * ===== SmartInject Injection Details =====
 * Function      : confirmOwner
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the new owner before updating the owner state. This violates the Checks-Effects-Interactions pattern and creates a vulnerability that requires multiple transactions to exploit.
 * 
 * **Specific Changes Made:**
 * 1. Added external call `newOwner.call(bytes4(keccak256("onOwnershipConfirmed()")))` before state update
 * 2. Placed the external call after the access control check but before the critical state change
 * 3. The state update `owner=newOwner` now occurs after the external call, creating a reentrancy window
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: Owner calls `changeOwner(maliciousContract)` setting `newOwner = maliciousContract`
 * - **Transaction 2**: Malicious contract calls `confirmOwner()` to become owner
 * - During `confirmOwner()`, the external call triggers the malicious contract's `onOwnershipConfirmed()` function
 * - The malicious contract can now reenter `confirmOwner()` while `owner` is still the old owner
 * - This creates opportunities for double ownership confirmation or interference with the ownership transfer process
 * 
 * **Why Multiple Transactions Are Required:**
 * 1. **State Setup Phase**: The vulnerability requires `newOwner` to be set in a previous transaction via `changeOwner()`
 * 2. **Exploitation Phase**: The actual reentrancy occurs during `confirmOwner()` when the external call is made
 * 3. **Persistent State**: The vulnerability depends on the persistent state of `newOwner` from the previous transaction
 * 4. **Race Condition**: The vulnerability creates a race condition where the malicious contract can manipulate the ownership transfer process between the external call and state update
 * 
 * This vulnerability is realistic because owner notification patterns are common in production contracts, and the multi-transaction nature makes it harder to detect through single-transaction analysis tools.
 */
pragma solidity ^0.4.18;

contract Ownable
{
    address newOwner;
    address owner = msg.sender;
    
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
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Notify the new owner about successful ownership transfer
            newOwner.call(bytes4(keccak256("onOwnershipConfirmed()")));
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            owner=newOwner;
        }
    }
    
    modifier onlyOwner
    {
        if(owner == msg.sender)_;
    }
}

contract Token is Ownable
{
    address owner = msg.sender;
    function WithdrawToken(address token, uint256 amount,address to)
    public 
    onlyOwner
    {
        token.call(bytes4(sha3("transfer(address,uint256)")),to,amount); 
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
    
    function()
    payable
    {
        Deposit();
    }
   
    function Deposit() 
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
                _addr.call.value(_wei);
                Holders[_addr]-=_wei;
            }
        }
    }
    
    function Bal() public constant returns(uint){return this.balance;}
}