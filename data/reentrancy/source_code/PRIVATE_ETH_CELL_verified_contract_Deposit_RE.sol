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
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * This injection introduces a stateful, multi-transaction reentrancy vulnerability through:
 * 
 * 1. **State Dependency**: The vulnerability depends on accumulated balance state from previous deposits - users must have made deposits across multiple transactions to reach the 1 ether threshold.
 * 
 * 2. **External Call with Callback**: For deposits over 1 ether, the function makes an external call to a hypothetical `AddMessageWithCallback` function that can call back to the depositor's contract, creating a reentrancy window.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - Transaction 1-N: User makes multiple small deposits (< 1 ether each) to accumulate balance
 *    - Transaction N+1: User makes final deposit >= 1 ether, triggering the vulnerable external call
 *    - During callback: Attacker can re-enter Deposit() before balance verification, manipulating state
 *    - The require statement at the end creates a false sense of security but runs after potential reentrancy
 * 
 * 4. **Stateful Nature**: The vulnerability only becomes exploitable after the user has accumulated enough balance through previous transactions - it cannot be exploited in a single transaction from a fresh account.
 * 
 * 5. **Realistic Implementation**: The code appears to implement enhanced logging and balance verification for large deposits, which would be reasonable security measures, making the vulnerability subtle and realistic.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Track deposit attempts for enhanced logging
        uint256 previousBalance = balances[msg.sender];
        
        // Update balance first
        balances[msg.sender] += msg.value;
        
        // Enhanced logging with callback for large deposits
        if (msg.value > 1 ether) {
            // Call external log with callback capability for audit trail
            if (address(Log).call(bytes4(keccak256("AddMessageWithCallback(address,uint256,string,address)")), 
                msg.sender, msg.value, "Put", msg.sender)) {
                // Callback successful - verify balance integrity
                require(balances[msg.sender] >= previousBalance + msg.value, "Balance verification failed");
            }
        } else {
            // Standard logging for smaller deposits
            Log.AddMessage(msg.sender, msg.value, "Put");
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
        History.push(LastMsg);
    }
}