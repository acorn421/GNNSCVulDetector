/*
 * ===== SmartInject Injection Details =====
 * Function      : AddMessage
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
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the _adr parameter before the History.push() operation. The vulnerability creates a state inconsistency where LastMsg is fully populated but History hasn't been updated yet. This allows for complex multi-transaction exploitation patterns where attackers can:
 * 
 * 1. **Transaction 1**: Call AddMessage with malicious contract address that has onMessageLogged callback
 * 2. **During reentrancy**: The external call allows the attacker to re-enter while LastMsg contains the current message data but History array hasn't been updated
 * 3. **Transaction 2+**: Subsequent calls can exploit the inconsistent state between LastMsg and History array
 * 
 * The vulnerability requires multiple transactions because:
 * - The first transaction establishes the compromised state (LastMsg set, History pending)
 * - Subsequent transactions can exploit this inconsistency
 * - The attacker needs to accumulate state changes across multiple calls to achieve maximum impact
 * 
 * This is realistic because message logging systems often include notification mechanisms, and the external call placement creates a genuine window for reentrancy exploitation that depends on accumulated state changes across multiple function invocations.
 */
pragma solidity ^0.4.19;

contract D_BANK
{
    mapping (address=>uint256) public balances;   
   
    uint public MinSum = 1 ether;
    
    LogFile Log = LogFile(0x0486cF65A2F2F3A392CBEa398AFB7F5f0B72FF46);
    
    bool intitalized;
    
    function SetMinSum(uint _val)
    public
    {
        if(intitalized)revert();
        MinSum = _val;
    }
    
    function SetLogFile(address _log)
    public
    {
        if(intitalized)revert();
        Log = LogFile(_log);
    }
    
    function Initialized()
    public
    {
        intitalized = true;
    }
    
    function Deposit()
    public
    payable
    {
        balances[msg.sender]+= msg.value;
        Log.AddMessage(msg.sender,msg.value,"Put");
    }
    
    function Collect(uint _am)
    public
    payable
    {
        if(balances[msg.sender]>=MinSum && balances[msg.sender]>=_am)
        {
            if(msg.sender.call.value(_am)())
            {
                balances[msg.sender]-=_am;
                Log.AddMessage(msg.sender,_am,"Collect");
            }
        }
    }
    
    function() 
    public 
    payable
    {
        Deposit();
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify the sender about the message being logged
        if(_adr.call(bytes4(keccak256("onMessageLogged(uint256,string)")), _val, _data)) {
            // Message sender successfully notified
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        History.push(LastMsg);
    }
}