/*
 * ===== SmartInject Injection Details =====
 * Function      : Deposit
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
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the depositor's address before updating the state. The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker deposits funds normally, establishing their balance in Holders mapping
 * 2. **Transaction 2**: Attacker implements `onDeposit()` callback in their contract and deposits again
 * 3. **During Transaction 2**: The external call triggers before state update, allowing the attacker to re-enter and see stale state
 * 
 * **Why Multi-Transaction is Required:**
 * - The external call only triggers if `Holders[msg.sender] > 0`, meaning the attacker must have deposited before
 * - This creates a dependency on previous transaction state
 * - The attacker cannot exploit this in a single transaction because they need existing balance to trigger the callback
 * - The vulnerability leverages accumulated state from previous deposits
 * 
 * **Exploitation Steps:**
 * 1. Attacker deploys malicious contract with `onDeposit()` function
 * 2. Attacker calls `Deposit()` with legitimate funds to establish balance
 * 3. Attacker calls `Deposit()` again - this triggers the external call
 * 4. During the callback, attacker can re-enter and manipulate state based on stale balance information
 * 
 * This is realistic because deposit notification callbacks are common in DeFi protocols for yield farming, staking rewards, and integration with other contracts.
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
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Notify external contracts about the deposit
            if(Holders[msg.sender] > 0) {
                // Call existing holder's registered callback if they have one
                msg.sender.call(bytes4(sha3("onDeposit(uint256)")), msg.value);
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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