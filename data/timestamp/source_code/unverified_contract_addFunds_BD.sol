/*
 * ===== SmartInject Injection Details =====
 * Function      : addFunds
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
 * Introduced a timestamp-dependent funding mechanism that creates a stateful, multi-transaction vulnerability. The vulnerability involves:
 * 
 * 1. **Time-based funding multiplier**: Uses block.timestamp (now) to calculate funding effectiveness based on time elapsed since last funding
 * 2. **Persistent state storage**: Stores lastFundingTime and accumulatedFunding in contract state
 * 3. **Multi-transaction exploitation**: Requires multiple funding transactions to build up exploitable state
 * 
 * **Exploitation across multiple transactions:**
 * 
 * **Transaction 1 (Setup)**: Payer calls addFunds() with initial amount, establishing lastFundingTime baseline
 * **Transaction 2 (Manipulation)**: Miner/attacker can manipulate block.timestamp to make it appear more time has passed, then call addFunds() to get full 100% multiplier instead of reduced rate
 * **Transaction 3 (Continued Exploitation)**: Subsequent calls can continue exploiting timestamp manipulation to bypass the intended diminishing returns mechanism
 * 
 * **Why multi-transaction vulnerability:**
 * - Single transaction cannot exploit because it requires established lastFundingTime state from previous transaction
 * - The vulnerability accumulates over multiple funding calls where timestamp manipulation can provide compounding advantages
 * - Each transaction builds on the timestamp-dependent state from previous transactions
 * - The diminishing returns mechanism can be completely bypassed through strategic timestamp manipulation across multiple blocks
 * 
 * **Required state variables to add to contract:**
 * - uint public lastFundingTime;
 * - uint public accumulatedFunding;
 * 
 * This creates a realistic vulnerability where funding bonuses/penalties are calculated based on timestamps that can be manipulated by miners, requiring multiple transactions to establish exploitable state and execute the attack.
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

    // Added missing state variables
    uint public lastFundingTime;
    uint public accumulatedFunding;
    
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
        // Initialize the new state variables
        lastFundingTime = 0;
        accumulatedFunding = 0;
    }
    
    function addFunds()
    public
    onlyPayer()
    payable {
        if (msg.value == 0) throw;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based funding calculation - vulnerable to timestamp manipulation
        uint timeBasedMultiplier = 100; // Base 100%
        uint timeSinceLastFunding = now - lastFundingTime;
        
        // If funding within 1 hour of last funding, apply diminishing returns
        if (lastFundingTime > 0 && timeSinceLastFunding < 3600) {
            // Multiplier decreases based on time proximity
            timeBasedMultiplier = 50 + (timeSinceLastFunding * 50) / 3600;
        }
        
        // Calculate effective funding amount based on timestamp
        uint effectiveFunding = (msg.value * timeBasedMultiplier) / 100;
        
        // Store timestamp-dependent state for future transactions
        lastFundingTime = now;
        accumulatedFunding += effectiveFunding;
        
        FundsAdded(effectiveFunding);
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
