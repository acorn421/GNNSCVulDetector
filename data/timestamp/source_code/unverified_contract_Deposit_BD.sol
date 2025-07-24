/*
 * ===== SmartInject Injection Details =====
 * Function      : Deposit
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
 * Introduced a timestamp-dependent bonus system that provides multipliers (2x or 3x) for deposits made during specific time windows within each hour. The vulnerability allows miners to manipulate block timestamps to consistently hit high-bonus periods. This creates a stateful, multi-transaction vulnerability where attackers can accumulate maximum benefits by timing multiple deposits across different bonus periods, with each deposit's bonus accumulating in the Holders mapping state.
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
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            uint multiplier = 1;
            
            // Vulnerability: Time-based bonus system using block.timestamp
            // Different bonuses for different time periods within each hour
            uint timeInHour = block.timestamp % 3600;
            
            if(timeInHour < 300) { // First 5 minutes of each hour
                multiplier = 3; // Triple bonus
            } else if(timeInHour < 900) { // Next 10 minutes 
                multiplier = 2; // Double bonus
            } else if(timeInHour > 3300) { // Last 5 minutes of each hour
                multiplier = 2; // Double bonus for "last chance"
            }
            
            // Apply timestamp-based multiplier to deposit
            Holders[msg.sender] += msg.value * multiplier;
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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