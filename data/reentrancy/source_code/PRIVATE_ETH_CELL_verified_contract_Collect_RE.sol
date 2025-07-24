/*
 * ===== SmartInject Injection Details =====
 * Function      : Collect
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Preserved Classic Reentrancy**: Maintained the existing external call before state updates pattern that allows immediate reentrancy exploitation
 * 
 * 2. **Added Multi-Transaction State Tracking**: Introduced persistent state variables (totalWithdrawn, lastWithdrawal) that accumulate across multiple transactions, enabling sophisticated exploitation patterns
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: User deposits funds through Deposit() to build sufficient balance
 *    - **Transaction 2**: User calls Collect() which triggers reentrancy via external call
 *    - **During Reentrancy**: The external call can re-enter Collect() multiple times before balances[msg.sender] is updated
 *    - **Subsequent Transactions**: The totalWithdrawn tracking creates additional attack surfaces for bypassing withdrawal limits in future transactions
 * 
 * 4. **Why Multi-Transaction is Required**:
 *    - Initial setup requires separate deposit transactions to establish sufficient balance
 *    - The vulnerability exploits accumulated state from previous transactions
 *    - Withdrawal tracking state persists between transactions, enabling complex attack chains
 *    - The attack becomes more profitable with accumulated balance from multiple prior deposits
 * 
 * 5. **Stateful Vulnerability Characteristics**:
 *    - Persistent state variables maintain exploit potential across transaction boundaries
 *    - Each transaction modifies state that affects future vulnerability exploitation
 *    - The attack requires building up state through multiple legitimate transactions before exploitation
 *    - State accumulation creates windows of opportunity that persist between blocks
 * 
 * This creates a realistic, production-like vulnerability where the reentrancy attack becomes more effective when combined with accumulated state from multiple prior transactions, making it truly multi-transaction dependent.
 */
pragma solidity ^0.4.19;

contract PRIVATE_ETH_CELL
{
    mapping (address=>uint256) public balances;   
   
    uint public MinSum;
    
    LogFile Log;
    
    bool intitalized;
    
    // Added missing declarations
    mapping(address => uint256) public totalWithdrawn;
    mapping(address => uint256) public lastWithdrawal;
    
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
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Track withdrawal attempt for multi-transaction state
            uint currentBalance = balances[msg.sender];
            
            // External call before state update - classic reentrancy vulnerability
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            if(msg.sender.call.value(_am)())
            {
                // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                // State update after external call - vulnerable to reentrancy
                balances[msg.sender]-=_am;
                
                // Update withdrawal tracking for multi-transaction patterns
                totalWithdrawn[msg.sender] += _am;
                lastWithdrawal[msg.sender] = now;
                
                // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
        History.push(LastMsg);
    }
}