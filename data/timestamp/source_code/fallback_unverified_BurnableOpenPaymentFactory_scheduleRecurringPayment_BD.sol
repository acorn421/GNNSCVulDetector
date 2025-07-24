/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleRecurringPayment
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue in a recurring payment system. The vulnerability is stateful and multi-transaction because: 1) First transaction schedules the recurring payment with scheduleRecurringPayment(), 2) Subsequent transactions call executeRecurringPayment() which relies on 'now' timestamp for validation, 3) The state persists across transactions through recurringPaymentActive, nextRecurringPaymentTime, and recurringPaymentCount variables. Miners can manipulate timestamps to either delay or accelerate payment execution, potentially draining funds faster than intended or preventing legitimate payments. The vulnerability requires multiple transactions to exploit - one to set up the recurring payment state, and subsequent ones to exploit the timestamp manipulation.
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
    

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    uint public recurringPaymentAmount;
    uint public recurringPaymentInterval;
    uint public nextRecurringPaymentTime;
    uint public recurringPaymentCount;
    bool public recurringPaymentActive;
    
    event RecurringPaymentScheduled(uint amount, uint interval);
    event RecurringPaymentExecuted(uint amount, uint count);
    event RecurringPaymentCanceled();
    
    function scheduleRecurringPayment(uint amount, uint intervalSeconds)
    public
    onlyPayer()
    inState(State.Committed)
    {
        recurringPaymentAmount = amount;
        recurringPaymentInterval = intervalSeconds;
        nextRecurringPaymentTime = now + intervalSeconds;
        recurringPaymentActive = true;
        recurringPaymentCount = 0;
        RecurringPaymentScheduled(amount, intervalSeconds);
    }
    
    function executeRecurringPayment()
    public
    inState(State.Committed)
    {
        if (!recurringPaymentActive) throw;
        if (now < nextRecurringPaymentTime) throw;
        if (this.balance < recurringPaymentAmount) throw;
        
        recurringPaymentCount++;
        nextRecurringPaymentTime = now + recurringPaymentInterval;
        
        bool success = internalRelease(recurringPaymentAmount);
        if (success) {
            RecurringPaymentExecuted(recurringPaymentAmount, recurringPaymentCount);
        }
    }
    
    function cancelRecurringPayment()
    public
    onlyPayer()
    {
        recurringPaymentActive = false;
        RecurringPaymentCanceled();
    }
    // === END FALLBACK INJECTION ===

    enum DefaultAction {None, Release, Burn}
    DefaultAction public defaultAction;
    uint public defaultTimeoutLength;
    uint public defaultTriggerTime;
    
    enum State {Open, Committed, Expended}
    State public state;
    
    modifier inState(State s) { if (s != state) throw; _; }
    modifier onlyPayer() { if (msg.sender != payer) throw; _; }
    modifier onlyRecipient() { if (msg.sender != recipient) throw; _; }
    modifier onlyPayerOrRecipient() { if ((msg.sender != payer) && (msg.sender != recipient)) throw; _; }
    
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
        PayerStringUpdated(payerString);
        commitThreshold = _commitThreshold;
        defaultAction = _defaultAction;
        defaultTimeoutLength = _defaultTimeoutLength;
    }
    
    function addFunds()
    public
    onlyPayer()
    payable {
        if (msg.value == 0) throw;
        FundsAdded(msg.value);
        if (state == State.Expended) {
            state = State.Committed;
            Unexpended();
        }
    }
    
    function recoverFunds()
    public
    onlyPayer()
    inState(State.Open)
    {
        FundsRecovered();
        selfdestruct(payer);
    }
    
    function commit()
    public
    inState(State.Open)
    payable
    {
        if (msg.value < commitThreshold) throw;
        recipient = msg.sender;
        state = State.Committed;
        Committed(recipient);
        
        if (this.balance == 0) {
            state = State.Expended;
            Expended();
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
            FundsBurned(amount);
        }
        if (this.balance == 0) {
            state = State.Expended;
            Expended();
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
            FundsReleased(amount);
        }
        if (this.balance == 0) {
            state = State.Expended;
            Expended();
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
        PayerStringUpdated(payerString);
    }
    
    function setRecipientString(string _string)
    public
    onlyRecipient()
    {
        recipientString = _string;
        RecipientStringUpdated(recipientString);
    }
    
    function delayDefaultAction()
    public
    onlyPayerOrRecipient()
    inState(State.Committed)
    {
        if (defaultAction == DefaultAction.None) throw;
        
        DefaultActionDelayed();
        defaultTriggerTime = now + defaultTimeoutLength;
    }
    
    function callDefaultAction()
    public
    onlyPayerOrRecipient()
    inState(State.Committed)
    {
        if (defaultAction == DefaultAction.None) throw;
        if (now < defaultTriggerTime) throw;
        
        DefaultActionCalled();
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
        address newBOPAddr = (new BurnableOpenPayment).value(msg.value)(payer, payerString, commitThreshold, defaultAction, defaultTimeoutLength);
        NewBOP(newBOPAddr);
        return newBOPAddr;
    }
}