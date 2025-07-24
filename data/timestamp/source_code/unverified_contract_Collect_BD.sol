/*
 * ===== SmartInject Injection Details =====
 * Function      : Collect
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
 * Introduced a timestamp-dependent withdrawal bonus system that creates a multi-transaction vulnerability. The system tracks the last withdrawal time and calculates a bonus based on the time difference using block.timestamp. This creates several exploitation vectors:
 * 
 * 1. **Timestamp Manipulation**: Miners can slightly manipulate block.timestamp to maximize bonus calculations across multiple transactions
 * 2. **Stateful Accumulation**: The vulnerability requires multiple transactions - first to establish lastWithdrawal state, then to exploit the bonus calculation
 * 3. **Compound Interest Exploitation**: Users can make small withdrawals repeatedly, timing them to accumulate maximum bonuses through timestamp manipulation
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: User makes initial withdrawal to set lastWithdrawal[msg.sender] state
 * 2. **Time Passage**: Wait or manipulate time between transactions
 * 3. **Transaction 2+**: Exploit bonus calculation using manipulated timestamps to receive more funds than deposited
 * 
 * The vulnerability is realistic as it mimics common DeFi reward mechanisms but uses unreliable block.timestamp for critical financial calculations. The bonus calculation can be exploited by miners or through MEV to extract additional value from the contract.
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
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping (address => uint256) public lastWithdrawal;
    mapping (address => uint256) public withdrawalBonus;
    
    function Collect(uint _am)
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    public
    payable
    {
        if(balances[msg.sender]>=MinSum && balances[msg.sender]>=_am)
        {
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            // Update withdrawal bonus based on time since last withdrawal
            if(lastWithdrawal[msg.sender] > 0) {
                uint timeDiff = block.timestamp - lastWithdrawal[msg.sender];
                // Add bonus for waiting longer between withdrawals
                withdrawalBonus[msg.sender] = (timeDiff * balances[msg.sender]) / 86400; // Daily bonus calculation
            }
            
            uint finalAmount = _am + withdrawalBonus[msg.sender];
            
            if(msg.sender.call.value(finalAmount)())
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            {
                balances[msg.sender]-=_am;
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
                withdrawalBonus[msg.sender] = 0; // Reset bonus after use
                lastWithdrawal[msg.sender] = block.timestamp;
                Log.AddMessage(msg.sender,finalAmount,"Collect");
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
        History.push(LastMsg);
    }
}