/*
 * ===== SmartInject Injection Details =====
 * Function      : Collect
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: The function now relies on `totalWithdrawals[msg.sender]` and `loyaltyBonus` - persistent state that accumulates across multiple transactions.
 * 
 * 2. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1-4**: User makes small withdrawals to accumulate `totalWithdrawals[msg.sender]` to reach 5 ether threshold
 *    - **Transaction 5+**: Once threshold is reached, user can exploit the reentrancy with bonus rewards
 *    - **Exploitation**: During the external call, attacker can reenter and drain funds with bonus multiplier
 * 
 * 3. **State Dependencies**: The vulnerability becomes more valuable over time as the attacker builds up their `totalWithdrawals` balance through legitimate transactions, making it stateful and multi-transaction dependent.
 * 
 * 4. **Classic Reentrancy Pattern**: External call (`msg.sender.call.value(withdrawalAmount)()`) occurs BEFORE state updates (`balances[msg.sender] -= _am`), allowing reentrant calls to bypass balance checks.
 * 
 * 5. **Realistic Business Logic**: The loyalty bonus system is a common DeFi pattern that justifies the complex state management and makes the vulnerability appear natural.
 * 
 * **Exploitation Sequence**:
 * 1. Attacker deposits funds and makes 4-5 small withdrawals to reach loyalty threshold
 * 2. On subsequent withdrawal, attacker triggers reentrancy during the external call
 * 3. Reentrant calls can drain more funds due to bonus multiplier and stale balance state
 * 4. The attack requires building up state over multiple transactions, making it stateful and multi-transaction dependent
 */
pragma solidity ^0.4.19;

contract D_BANK
{
    mapping (address=>uint256) public balances;   
   
    uint public MinSum = 1 ether;
    
    LogFile Log = LogFile(0x0486cF65A2F2F3A392CBEa398AFB7F5f0B72FF46);
    
    bool intitalized;

    // Fix: declare totalWithdrawals mapping and loyaltyBonus variable
    mapping(address => uint256) public totalWithdrawals;
    uint public loyaltyBonus = 10; // for example, 10% bonus
    
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
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Store withdrawal amount for potential reward calculation
            uint withdrawalAmount = _am;
            
            // Check if user qualifies for loyalty bonus (accumulated over multiple transactions)
            if(totalWithdrawals[msg.sender] >= 5 ether) {
                withdrawalAmount = _am + ((_am * loyaltyBonus) / 100);
            }
            
            // Process withdrawal with external call BEFORE state updates
            if(msg.sender.call.value(withdrawalAmount)()) {
                // Update state AFTER external call - classic reentrancy vulnerability
                balances[msg.sender] -= _am;
                
                // Track total withdrawals for loyalty program
                totalWithdrawals[msg.sender] += _am;
                
                // Reset withdrawal count after reaching threshold
                if(totalWithdrawals[msg.sender] >= 10 ether) {
                    totalWithdrawals[msg.sender] = 0;
                }
                
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