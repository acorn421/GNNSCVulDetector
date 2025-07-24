/*
 * ===== SmartInject Injection Details =====
 * Function      : AddMessage
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability that:
 * 
 * 1. **Specific Changes Made:**
 *    - Added time-based privilege escalation logic using block.number as a time proxy
 *    - Implemented a "priority" system that activates when messages are submitted within 256 blocks of a previous message from the same sender
 *    - Priority messages get double value and use `now` timestamp, while regular messages use `block.number * 15` as timestamp approximation
 *    - Added state traversal through History array to find previous messages from the same sender
 * 
 * 2. **Multi-Transaction Exploitation:**
 *    - **Transaction 1**: Attacker calls AddMessage() to establish baseline state in History array
 *    - **Transaction 2+**: Attacker (or miner) calls AddMessage() within 256 blocks, triggering priority escalation
 *    - **Miner Manipulation**: Miners can manipulate block.number progression to extend the 256-block window
 *    - **State Accumulation**: Each call builds up History state, and the vulnerability relies on comparing current block.number with stored historical block-derived timestamps
 * 
 * 3. **Why Multiple Transactions Required:**
 *    - The vulnerability requires historical state (previous messages in History array) to be exploitable
 *    - First transaction establishes the baseline state with timestamp
 *    - Subsequent transactions within the 256-block window can exploit the time-based privilege escalation
 *    - Single transaction cannot exploit this as it requires comparing against previously stored state from earlier blocks
 *    - The block.number comparison mechanism inherently requires multiple blocks/transactions to be meaningful
 * 
 * 4. **Realistic Attack Vector:**
 *    - Miners can manipulate block timestamps and block.number progression
 *    - Users can strategically time their transactions to fall within the vulnerable window
 *    - The 256-block window (roughly 1 hour) provides practical exploitation timeframe
 *    - Priority escalation with doubled values creates clear economic incentive for exploitation
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Timestamp-based privilege escalation vulnerability
        // If this message is added within 256 blocks of the last message
        // from the same sender, grant special "priority" status
        bool isPriority = false;
        if (History.length > 0) {
            for (uint i = History.length - 1; i >= 0; i--) {
                if (History[i].Sender == _adr) {
                    // Use block.number as time proxy - vulnerable to miner manipulation
                    uint blockDiff = block.number - (History[i].Time / 15); // Assuming 15 sec blocks
                    if (blockDiff < 256) {
                        isPriority = true;
                        // Priority messages get elevated permissions in state
                        _val = _val * 2; // Double the value for priority messages
                    }
                    break;
                }
                if (i == 0) break; // Prevent underflow
            }
        }
        
        LastMsg.Sender = _adr;
        // Store block.number * 15 as time approximation - vulnerable to manipulation
        LastMsg.Time = isPriority ? now : block.number * 15;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        LastMsg.Val = _val;
        LastMsg.Data = _data;
        History.push(LastMsg);
    }
}