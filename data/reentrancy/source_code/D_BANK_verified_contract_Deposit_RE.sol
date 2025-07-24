/*
 * ===== SmartInject Injection Details =====
 * Function      : Deposit
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a callback mechanism that allows depositors to register callback contracts. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1 - Setup Phase:**
 * - Attacker calls a new function `registerDepositCallback(address _callback)` to register a malicious callback contract
 * - This sets up the persistent state in the `depositCallbacks` mapping
 * 
 * **Transaction 2 - Exploitation Phase:**
 * - Attacker calls `Deposit()` with ETH
 * - The function calls the registered callback contract BEFORE updating the balance
 * - During the callback, the malicious contract can re-enter `Deposit()` or other functions
 * - Since the balance hasn't been updated yet, the attacker can exploit this timing window
 * 
 * **Multi-Transaction Requirements:**
 * 1. **State Persistence**: The `depositCallbacks` mapping maintains state between transactions
 * 2. **Sequential Dependency**: Must first register callback, then exploit during deposit
 * 3. **Accumulated State**: Multiple deposits can be made to accumulate vulnerable state
 * 4. **Cross-Function Exploitation**: The reentrancy can target other functions like `Collect()` while balances are in inconsistent state
 * 
 * **Exploitation Scenario:**
 * - Attacker registers malicious callback contract
 * - Attacker deposits ETH, triggering callback before balance update
 * - Callback re-enters `Collect()` function, which still sees old balance state
 * - Attacker can drain more ETH than deposited due to state inconsistency
 * 
 * This creates a realistic vulnerability where the external call occurs before state updates, violating the Checks-Effects-Interactions pattern and enabling cross-function reentrancy attacks.
 */
pragma solidity ^0.4.19;

contract D_BANK
{
    mapping (address=>uint256) public balances;
    
    uint public MinSum = 1 ether;
    
    LogFile Log = LogFile(0x0486cF65A2F2F3A392CBEa398AFB7F5f0B72FF46);
    
    bool intitalized;

    // Added missing mapping and interface for depositCallbacks
    mapping(address => address) public depositCallbacks;
    
    function setDepositCallback(address callback) public {
        depositCallbacks[msg.sender] = callback;
    }
    
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        require(msg.value > 0, "Deposit amount must be greater than 0");
        
        // Add support for deposit notifications to registered callbacks
        if (depositCallbacks[msg.sender] != address(0)) {
            // External call BEFORE state update - creates reentrancy vulnerability
            IDepositCallback(depositCallbacks[msg.sender]).onDeposit(msg.value);
        }
        
        // State update happens after external call - vulnerable to reentrancy
        balances[msg.sender] += msg.value;
        Log.AddMessage(msg.sender, msg.value, "Put");
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

// Added the missing interface for IDepositCallback
interface IDepositCallback {
    function onDeposit(uint256 amount) external;
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
