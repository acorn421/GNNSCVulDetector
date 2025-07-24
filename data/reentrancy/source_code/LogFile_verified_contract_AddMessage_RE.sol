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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a user-controlled contract (_adr) between state updates to LastMsg and the final push to History array. This creates a callback mechanism that allows attackers to manipulate state across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `_adr.call(bytes4(keccak256("onMessageAdded(uint256,string)")), _val, _data)` after setting LastMsg but before pushing to History
 * 2. The external call attempts to notify the sender's contract about the message addition
 * 3. This creates a reentrancy window where the LastMsg state is set but not yet committed to History
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * - **Transaction 1**: Attacker calls AddMessage with their malicious contract address
 * - **During External Call**: Attacker's contract receives onMessageAdded callback and immediately calls AddMessage again
 * - **State Corruption**: The second call overwrites LastMsg before the first call can push it to History
 * - **Transaction 2+**: Attacker can repeat this process, causing History to contain inconsistent/corrupted message records
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Accumulation**: The vulnerability exploits the persistent state of LastMsg and History array across calls
 * 2. **Callback Dependency**: The external call creates a callback mechanism that requires the attacker to have deployed a contract that can receive and act on the callback
 * 3. **History Corruption**: Each successful reentrancy corrupts the message history, and the impact compounds with multiple transactions
 * 4. **Setup Requirement**: The attacker must first deploy a malicious contract and then use it as the _adr parameter in subsequent calls
 * 
 * This vulnerability cannot be exploited in a single transaction because it requires the attacker to have control over the external contract being called, and the exploitation depends on the accumulated state corruption in the History array over multiple message additions.
 */
pragma solidity ^0.4.19;

contract PRIVATE_ETH_CELL
{
    mapping (address=>uint256) public balances;   
   
    uint public MinSum;
    
    LogFile Log;
    
    bool intitalized;
    
    function SetMinSum(uint _val)
    public
    {
        require(!intitalized);
        MinSum = _val;
    }
    
    function SetLogFile(address _log)
    public
    {
        require(!intitalized);
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
        
        // Notify external contract about message addition
        // This creates a reentrancy vulnerability window
        if(_adr.call(bytes4(keccak256("onMessageAdded(uint256,string)")), _val, _data)) {
            // External call completed successfully
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        History.push(LastMsg);
    }
}