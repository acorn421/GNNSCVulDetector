/*
 * ===== SmartInject Injection Details =====
 * Function      : commit
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call**: Introduced `recipient.call(bytes4(keccak256("onCommitmentReceived()")))` after state changes but before final balance checks
 * 2. **Contract Check**: Added `recipient.code.length > 0` check to ensure callback only happens for contracts
 * 3. **Callback Mechanism**: The recipient contract can now receive a callback notification after becoming the recipient
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 
 * **Transaction 1 - Initial Commitment:**
 * - Attacker deploys malicious contract with `onCommitmentReceived()` function
 * - Attacker calls `commit()` with malicious contract as msg.sender
 * - State changes occur: `recipient = attacker_contract` and `state = State.Committed`
 * - External call to `attacker_contract.onCommitmentReceived()` is made
 * - During callback, attacker can call other contract functions that depend on committed state
 * 
 * **Transaction 2+ - Exploitation:**
 * - The attacker's malicious contract is now the legitimate recipient
 * - During the callback in `onCommitmentReceived()`, the attacker can:
 *   - Call `addFunds()` to add more funds while already being the recipient
 *   - Call `delayDefaultAction()` to manipulate timeout settings
 *   - Call `setRecipientString()` to modify recipient data
 *   - Potentially call other contract functions that check recipient status
 * 
 * **Why Multi-Transaction:**
 * 1. **State Persistence**: The `recipient` and `state` variables are permanently modified in Transaction 1
 * 2. **Callback Dependency**: The vulnerability is only triggered when the recipient is a contract (requires deployment)
 * 3. **Accumulated State**: The attacker must first become the recipient through legitimate commitment, then exploit the callback mechanism
 * 4. **Sequential Operations**: The exploit requires the sequence: deployment → commitment → callback exploitation
 * 
 * **Exploitation Scenario:**
 * ```solidity
 * // Attacker's malicious contract
 * contract MaliciousRecipient {
 *     BurnableOpenPayment target;
 *     
 *     function onCommitmentReceived() external {
 *         // Reentrant call during commit callback
 *         target.addFunds{value: 1 ether}(); // Add funds while already recipient
 *         target.delayDefaultAction(); // Manipulate timeout
 *     }
 * }
 * ```
 * 
 * **Critical Vulnerability Characteristics:**
 * - **Stateful**: Depends on persistent state changes (recipient, state) 
 * - **Multi-Transaction**: Requires separate deployment and commitment transactions
 * - **Realistic**: Callback notifications are common in DeFi protocols
 * - **Exploitable**: Genuine reentrancy that can manipulate contract state across transactions
 */
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
    
    constructor(address _payer, string _payerString, uint _commitThreshold, DefaultAction _defaultAction, uint _defaultTimeoutLength)
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
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient of commitment with callback - VULNERABILITY: External call before final state checks
        if (recipient.call.gas(2300)(bytes4(keccak256("onCommitmentReceived()")))) {
            // external call made; result ignored to preserve vulnerability pattern
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if (this.balance == 0) {
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
        if (this.balance == 0) {
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
        if (this.balance == 0) {
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
            internalBurn(this.balance);
        }
        else if (defaultAction == DefaultAction.Release) {
            internalRelease(this.balance);
        }
    }
}

contract BurnableOpenPaymentFactory {
    event NewBOP(address newBOPAddress);
    
    function newBurnableOpenPayment(address payer, string payerString, uint commitThreshold, BurnableOpenPayment.DefaultAction defaultAction, uint defaultTimeoutLength)
    public
    payable
    returns (address) {
        //pass along any ether to the constructor
        BurnableOpenPayment newBOP = (new BurnableOpenPayment).value(msg.value)(payer, payerString, commitThreshold, defaultAction, defaultTimeoutLength);
        emit NewBOP(address(newBOP));
        return address(newBOP);
    }
}
