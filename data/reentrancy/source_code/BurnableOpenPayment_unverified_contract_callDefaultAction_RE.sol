/*
 * ===== SmartInject Injection Details =====
 * Function      : callDefaultAction
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Injected a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Inlined External Calls**: Replaced calls to internalBurn() and internalRelease() with direct .send() operations, placing external calls before state updates.
 * 
 * 2. **State Updates After External Calls**: Moved critical state updates (setting state to Expended) to occur after the external .send() calls, creating a classic reentrancy vulnerability window.
 * 
 * 3. **Added defaultTriggerTime Reset**: Added a line that resets defaultTriggerTime after external calls, which is the key to making this a multi-transaction vulnerability.
 * 
 * **Multi-Transaction Exploitation Path:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious recipient contract
 * - Attacker calls commit() to become the recipient
 * - Attacker waits for defaultTriggerTime to pass
 * 
 * **Transaction 2 (First Exploit Call):**
 * - Attacker calls callDefaultAction()
 * - During the recipient.send() callback, the malicious contract:
 *   - Notices that defaultTriggerTime hasn't been reset yet
 *   - Calls callDefaultAction() again (reentrancy)
 *   - The second call succeeds because state is still Committed and defaultTriggerTime hasn't been updated
 *   - However, the reentrant call also triggers the defaultTriggerTime reset at the end
 * 
 * **Transaction 3 (Second Exploit Call):**
 * - After the first transaction completes, the attacker calls callDefaultAction() again
 * - This works because defaultTriggerTime was reset to now + defaultTimeoutLength
 * - If the attacker can manipulate time or wait, they can call it again
 * - Each call drains more funds while the state remains Committed due to the race condition
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability relies on the defaultTriggerTime being reset after external calls
 * - The first transaction establishes the reentrancy and resets the timer
 * - Subsequent transactions can exploit the reset timer to make additional calls
 * - The state changes persist between transactions, allowing continued exploitation
 * - Single-transaction exploitation is limited by gas costs and the specific timing logic
 * 
 * The vulnerability creates a scenario where an attacker can repeatedly drain funds across multiple transactions by exploiting the combination of reentrancy and the time-based reset mechanism.
 */
//A BurnableOpenPayment is instantiated with a specified payer and a commitThreshold.
//The recipient is not set when the contract is instantiated.

//The constructor is payable, so the contract can be instantiated with initial funds.
//Only the payer can fund the Payment after instantiation.

//All behavior of the contract is directed by the payer, but
//the payer can never directly recover the payment unless he becomes the recipient.

//Anyone can become the recipient by contributing the commitThreshold.
//The recipient cannot change once it's been set.

//The payer can at any time choose to burn or release to the recipient any amount of funds.

pragma solidity ^0.4.10;

contract BurnableOpenPayment {
    address public payer;
    address public recipient;
    address constant burnAddress = 0x0;
    
    string public payerString;
    string public recipientString;
    
    uint public commitThreshold;
    
    enum DefaultAction {None, Release, Burn}
    DefaultAction public defaultAction;
    uint public defaultTimeoutLength;
    uint public defaultTriggerTime;
    
    enum State {Open, Committed, Expended}
    State public state;
    
    modifier inState(State s) { if (s != state) revert(); _; }
    modifier onlyPayer() { if (msg.sender != payer) revert(); _; }
    modifier onlyRecipient() { if (msg.sender != recipient) revert(); _; }
    modifier onlyPayerOrRecipient() { if ((msg.sender != payer) && (msg.sender != recipient)) revert(); _; }
    
    event FundsAdded(uint amount);
    event PayerStringUpdated(string newPayerString);
    event RecipientStringUpdated(string newRecipientString);
    event FundsRecovered();
    event Committed(address recipient);
    event FundsBurned(uint amount);
    event FundsReleased(uint amount);
    event Expended();
    event Unexpended();
    event DefaultActionDelayed();
    event DefaultActionCalled();
    
    function BurnableOpenPayment(address _payer, string _payerString, uint _commitThreshold, DefaultAction _defaultAction, uint _defaultTimeoutLength)
    public
    payable {
        state = State.Open;
        payer = _payer;
        payerString = _payerString;
        emit PayerStringUpdated(payerString);
        commitThreshold = _commitThreshold;
        defaultAction = _defaultAction;
        defaultTimeoutLength = _defaultTimeoutLength;
    }
    
    function addFunds()
    public
    onlyPayer()
    payable {
        if (msg.value == 0) revert();
        emit FundsAdded(msg.value);
        if (state == State.Expended) {
            state = State.Committed;
            emit Unexpended();
        }
    }
    
    function recoverFunds()
    public
    onlyPayer()
    inState(State.Open)
    {
        emit FundsRecovered();
        selfdestruct(payer);
    }
    
    function commit()
    public
    inState(State.Open)
    payable
    {
        if (msg.value < commitThreshold) revert();
        recipient = msg.sender;
        state = State.Committed;
        emit Committed(recipient);
        
        if (address(this).balance == 0) {
            state = State.Expended;
            emit Expended();
        }
        
        if (defaultAction != DefaultAction.None) {
            defaultTriggerTime = now + defaultTimeoutLength;
        }
    }
    
    function internalBurn(uint amount)
    private
    inState(State.Committed)
    returns (bool)
    {
        bool success = burnAddress.send(amount);
        if (success) {
            emit FundsBurned(amount);
        }
        if (address(this).balance == 0) {
            state = State.Expended;
            emit Expended();
        }
        return success;
    }
    
    function burn(uint amount)
    public
    inState(State.Committed)
    onlyPayer()
    returns (bool)
    {
        return internalBurn(amount);
    }
    
    function internalRelease(uint amount)
    private
    inState(State.Committed)
    returns (bool)
    {
        bool success = recipient.send(amount);
        if (success) {
            emit FundsReleased(amount);
        }
        if (address(this).balance == 0) {
            state = State.Expended;
            emit Expended();
        }
        return success;
    }
    
    function release(uint amount)
    public
    inState(State.Committed)
    onlyPayer()
    returns (bool)
    {
        return internalRelease(amount);
    }
    
    function setPayerString(string _string)
    public
    onlyPayer()
    {
        payerString = _string;
        emit PayerStringUpdated(payerString);
    }
    
    function setRecipientString(string _string)
    public
    onlyRecipient()
    {
        recipientString = _string;
        emit RecipientStringUpdated(recipientString);
    }
    
    function delayDefaultAction()
    public
    onlyPayerOrRecipient()
    inState(State.Committed)
    {
        if (defaultAction == DefaultAction.None) revert();
        
        emit DefaultActionDelayed();
        defaultTriggerTime = now + defaultTimeoutLength;
    }
    
    function callDefaultAction()
    public
    onlyPayerOrRecipient()
    inState(State.Committed)
    {
        if (defaultAction == DefaultAction.None) revert();
        if (now < defaultTriggerTime) revert();
        
        emit DefaultActionCalled();
        if (defaultAction == DefaultAction.Burn) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Vulnerable: External call before state updates
            bool burnSuccess = burnAddress.send(address(this).balance);
            if (burnSuccess) {
                emit FundsBurned(address(this).balance);
            }
            // State update after external call - vulnerable to reentrancy
            if (address(this).balance == 0) {
                state = State.Expended;
                emit Expended();
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        }
        else if (defaultAction == DefaultAction.Release) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Vulnerable: External call before state updates
            bool releaseSuccess = recipient.send(address(this).balance);
            if (releaseSuccess) {
                emit FundsReleased(address(this).balance);
            }
            // State update after external call - vulnerable to reentrancy
            if (address(this).balance == 0) {
                state = State.Expended;
                emit Expended();
            }
        }
        
        // Critical vulnerability: Reset defaultTriggerTime after external calls
        // This allows multiple calls if reentrancy occurs
        defaultTriggerTime = now + defaultTimeoutLength;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
}

contract BurnableOpenPaymentFactory {
    event NewBOP(address newBOPAddress);
    
    function newBurnableOpenPayment(address payer, string payerString, uint commitThreshold, BurnableOpenPayment.DefaultAction defaultAction, uint defaultTimeoutLength)
    public
    payable
    returns (address) {
        //pass along any ether to the constructor
        address newBOPAddr = (new BurnableOpenPayment).value(msg.value)(payer, payerString, commitThreshold, defaultAction, defaultTimeoutLength);
        emit NewBOP(newBOPAddr);
        return newBOPAddr;
    }
}
