/*
 * ===== SmartInject Injection Details =====
 * Function      : WithdrawToHolder
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a timestamp-dependent daily withdrawal limit system that uses block.timestamp to track withdrawal periods. The vulnerability requires multiple transactions to exploit: 1) Initial withdrawals to establish state in lastWithdrawDay and dailyWithdrawn mappings, 2) Miner manipulation of block.timestamp to reset daily limits prematurely, allowing exceeding intended withdrawal limits across multiple transactions. The vulnerability is stateful (persists withdrawal tracking data) and multi-transaction (requires setup phase and exploitation phase). Miners can manipulate block.timestamp within ~15 second tolerance to bypass the daily reset mechanism.
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
    // --- ADDED missing variable declarations for dailyWithdrawn and lastWithdrawDay ---
    mapping(address => uint) public dailyWithdrawn;
    mapping(address => uint) public lastWithdrawDay;
    
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
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
                // Timestamp dependence vulnerability: daily withdrawal limit resets
                uint dailyLimit = 10 ether;
                uint currentDay = block.timestamp / 86400; // seconds in a day
                
                // Initialize tracking if first withdrawal
                if(lastWithdrawDay[_addr] == 0) {
                    lastWithdrawDay[_addr] = currentDay;
                    dailyWithdrawn[_addr] = 0;
                }
                
                // Reset daily limit if new day (vulnerable to timestamp manipulation)
                if(currentDay > lastWithdrawDay[_addr]) {
                    dailyWithdrawn[_addr] = 0;
                    lastWithdrawDay[_addr] = currentDay;
                }
                
                // Check if withdrawal exceeds daily limit
                if(dailyWithdrawn[_addr] + _wei <= dailyLimit) {
                    _addr.call.value(_wei)();
                    Holders[_addr]-=_wei;
                    dailyWithdrawn[_addr] += _wei;
                }
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            }
        }
    }
    
    function Bal() public constant returns(uint){return this.balance;}
}
