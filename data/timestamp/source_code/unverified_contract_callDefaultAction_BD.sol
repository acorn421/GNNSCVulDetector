/*
 * ===== SmartInject Injection Details =====
 * Function      : callDefaultAction
 * Vulnerability : Timestamp Dependence
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
 * Injected a stateful, multi-transaction timestamp dependence vulnerability through time-based bonus calculations. The vulnerability allows attackers to manipulate block timestamps across multiple transactions to maximize time-based bonuses. 
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * 1. **Setup Phase (Transaction 1):** Attacker calls `delayDefaultAction()` to reset `defaultTriggerTime = now + defaultTimeoutLength`, establishing the baseline timestamp in contract state.
 * 
 * 2. **Timing Manipulation (Transaction 2):** Attacker waits or colludes with miners to manipulate subsequent block timestamps to create a larger `timeSinceCommit` value when `callDefaultAction()` is called.
 * 
 * 3. **Exploitation Phase (Transaction 3):** Attacker calls `callDefaultAction()` with manipulated timestamps to maximize the `timeBasedBonus` calculation, effectively stealing funds through inflated bonus calculations.
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires `defaultTriggerTime` to be set in a prior transaction (via `delayDefaultAction()` or initial contract commitment)
 * - Block timestamp manipulation requires coordination across multiple blocks/transactions
 * - The bonus calculation depends on the time difference between the stored `defaultTriggerTime` (from previous transaction) and the current `now` (current transaction)
 * - Cannot be exploited atomically as it requires state persistence of timing values between transactions
 * 
 * **Realistic Vulnerability Pattern:**
 * - Time-based bonuses are common in DeFi protocols
 * - Using `block.timestamp` for financial calculations is a known anti-pattern
 * - The vulnerability appears as a legitimate feature but creates timing attack surface
 * - Miners can manipulate timestamps within ~900 seconds, making this practically exploitable
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
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Vulnerability: Time-based bonus calculation using block.timestamp
        // This creates a multi-transaction timing attack surface
        uint256 timeSinceCommit = now - defaultTriggerTime;
        uint256 timeBasedBonus = 0;
        
        // Calculate bonus based on how much time has passed since trigger time
        if (timeSinceCommit > 0) {
            // Bonus increases linearly with time, capped at 10% of balance
            timeBasedBonus = (this.balance * timeSinceCommit) / (10 * defaultTimeoutLength);
            if (timeBasedBonus > this.balance / 10) {
                timeBasedBonus = this.balance / 10;
            }
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        DefaultActionCalled();
        if (defaultAction == DefaultAction.Burn) {
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            // Apply time-based bonus to burn more funds
            uint256 burnAmount = this.balance;
            if (timeBasedBonus > 0 && burnAmount > timeBasedBonus) {
                burnAmount = burnAmount - timeBasedBonus; // Reduce burn, effectively giving bonus
            }
            internalBurn(burnAmount);
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        }
        else if (defaultAction == DefaultAction.Release) {
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            // Apply time-based bonus to release calculation
            uint256 releaseAmount = this.balance + timeBasedBonus;
            if (releaseAmount > this.balance) {
                releaseAmount = this.balance; // Cap at actual balance
            }
            internalRelease(releaseAmount);
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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