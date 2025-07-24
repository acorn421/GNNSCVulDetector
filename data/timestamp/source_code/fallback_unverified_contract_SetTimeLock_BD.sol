/*
 * ===== SmartInject Injection Details =====
 * Function      : SetTimeLock
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence through a time-locked withdrawal system. The vulnerability is stateful and multi-transaction as it requires: 1) First calling SetTimeLock to establish a lock period, 2) Then waiting for the supposed time period to pass, 3) Finally calling TimedWithdraw to execute the withdrawal. The vulnerability allows malicious miners to manipulate block timestamps within the allowed range (not smaller than previous block, not too far in future) to either prevent withdrawals by keeping timestamps low or enable premature withdrawals by advancing timestamps. The state persists between transactions through the TimeLocks mapping.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    mapping (address => uint) public TimeLocks;
    
    function SetTimeLock(address _addr, uint _lockTime) 
    public
    onlyOwner
    {
        TimeLocks[_addr] = now + _lockTime;
    }
    
    function TimedWithdraw(address _addr, uint _wei) 
    public
    onlyOwner
    {
        if(Holders[_addr] >= _wei && now >= TimeLocks[_addr])
        {
            _addr.call.value(_wei);
            Holders[_addr] -= _wei;
        }
    }
    // === END FALLBACK INJECTION ===

}