/*
 * ===== SmartInject Injection Details =====
 * Function      : Put
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Reordered Operations**: Moved the Log.AddMessage() call to occur BEFORE state updates, violating the Checks-Effects-Interactions pattern. This allows reentrancy to read stale state.
 * 
 * 2. **Added Callback Mechanism**: Introduced a new external call to msg.sender.call() that triggers an "onDeposit" callback after state modifications. This creates a reentrancy window where an attacker can manipulate the updated state.
 * 
 * 3. **Stateful Exploitation Requirements**: The vulnerability requires multiple transactions because:
 *    - Transaction 1: Attacker deposits funds normally, establishing baseline state
 *    - Transaction 2: Attacker deposits again, but their malicious contract's onDeposit callback can re-enter Put() function
 *    - During reentrancy, the attacker sees the accumulated balance from previous transactions
 *    - Multiple rounds compound the effect, allowing balance manipulation across transaction boundaries
 * 
 * 4. **Multi-Transaction Dependency**: The vulnerability is only exploitable across multiple calls because:
 *    - The MinSum check requires accumulated balance from previous deposits
 *    - The callback only triggers when acc.balance > MinSum, requiring state buildup
 *    - Reentrancy manipulates persistent state that carries forward to subsequent transactions
 * 
 * The attack vector allows an attacker to manipulate their accumulated balance and unlock times across multiple transactions by re-entering during the callback phase when state has already been modified but the transaction hasn't completed.
 */
pragma solidity ^0.4.19;

contract COIN_BOX   
{
    struct Holder   
    {
        uint unlockTime;
        uint balance;
    }
    
    mapping (address => Holder) public Acc;
    
    uint public MinSum;
    
    LogFile Log;
    
    bool intitalized;
    
    function SetMinSum(uint _val)
    public
    {
        if(intitalized)throw;
        MinSum = _val;
    }
    
    function SetLogFile(address _log)
    public
    {
        if(intitalized)throw;
        Log = LogFile(_log);
    }
    
    function Initialized()
    public
    {
        intitalized = true;
    }
    
    function Put(uint _lockTime)
    public
    payable
    {
        var acc = Acc[msg.sender];
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Vulnerable: External call before state updates
        // This allows reentrancy to read/manipulate old state
        Log.AddMessage(msg.sender,msg.value,"Put");
        
        // State updates happen after external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        acc.balance += msg.value;
        if(now+_lockTime>acc.unlockTime)acc.unlockTime=now+_lockTime;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Additional callback that enables multi-transaction stateful reentrancy
        // Attacker can set up malicious callback contract to re-enter
        if(msg.value > 0 && acc.balance > MinSum) {
            // Call to user-controlled contract before final state commitment
            if(!msg.sender.call(bytes4(keccak256("onDeposit(uint256)")), msg.value)) {
                // Silent failure - state already modified above
            }
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
    
    function Collect(uint _am)
    public
    payable
    {
        var acc = Acc[msg.sender];
        if( acc.balance>=MinSum && acc.balance>=_am && now>acc.unlockTime)
        {
            if(msg.sender.call.value(_am)())
            {
                acc.balance-=_am;
                Log.AddMessage(msg.sender,_am,"Collect");
            }
        }
    }
    
    function() 
    public 
    payable
    {
        Put(0);
    }
    
}


contract LogFile
{
    struct Message
    {
        address Sender;
        string  Data;
        uint Val;
        uint  Time;
    }
    
    Message[] public History;
    
    Message LastMsg;
    
    function AddMessage(address _adr,uint _val,string _data)
    public
    {
        LastMsg.Sender = _adr;
        LastMsg.Time = now;
        LastMsg.Val = _val;
        LastMsg.Data = _data;
        History.push(LastMsg);
    }
}