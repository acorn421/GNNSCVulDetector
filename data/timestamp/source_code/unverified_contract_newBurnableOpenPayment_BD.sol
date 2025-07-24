/*
 * ===== SmartInject Injection Details =====
 * Function      : newBurnableOpenPayment
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by implementing a time-based fee structure that relies on block.timestamp for critical fee calculations. The vulnerability requires multiple transactions to exploit:
 * 
 * **Changes Made:**
 * 1. Added state variables `lastCreationTime` mapping and fee-related variables
 * 2. Implemented time-based fee calculation using `block.timestamp`
 * 3. Added state tracking of user's last creation time
 * 4. Made fee dependent on time elapsed since last creation
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1 (Setup)**: User calls function for first time, pays full fee, `lastCreationTime` is set
 * 2. **Transaction 2 (Exploitation)**: User waits and calls again, potentially paying reduced fee due to timestamp manipulation
 * 
 * **Exploitation Vector:**
 * - Miners can manipulate `block.timestamp` (±15 seconds tolerance) to:
 *   - Artificially increase `timeSinceLastCreation` in Transaction 2
 *   - Reduce the required fee below market rates
 *   - Enable users to create contracts at unfairly low costs
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability depends on the persistent state (`lastCreationTime`) being set in a previous transaction
 * - The fee calculation compares current `block.timestamp` with stored historical timestamp
 * - Single transaction cannot exploit this as it requires comparison with a previously stored timestamp
 * - The accumulated time difference is what creates the vulnerability surface
 * 
 * **Real-World Impact:**
 * - Users could coordinate with miners to manipulate timestamps
 * - Unfair fee advantages for users who can influence block timestamps
 * - Economic exploitation of the factory's fee structure
 * - Potential for timestamp manipulation attacks across multiple contract creations
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
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
// State variables for fee calculation (add to contract)
mapping(address => uint) public lastCreationTime;
uint public baseFee = 0.01 ether;
uint public feeMultiplier = 100; // Basis points

// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
function newBurnableOpenPayment(address payer, string payerString, uint commitThreshold, BurnableOpenPayment.DefaultAction defaultAction, uint defaultTimeoutLength)
    public
    payable
    returns (address) {
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Calculate time-based fee using block.timestamp
        uint timeSinceLastCreation = block.timestamp - lastCreationTime[msg.sender];
        uint requiredFee = baseFee;
        
        // Fee decreases over time, but uses unsafe timestamp arithmetic
        if (timeSinceLastCreation > 0) {
            // Vulnerable: Using block.timestamp for fee calculation
            // Fee reduces by 1% every 10 seconds, can be manipulated by miners
            uint feeReduction = (timeSinceLastCreation / 10 seconds) * (baseFee / feeMultiplier);
            if (feeReduction < baseFee) {
                requiredFee = baseFee - feeReduction;
            } else {
                requiredFee = baseFee / 10; // Minimum fee
            }
        }
        
        // Vulnerable: State-dependent fee check based on timestamp
        if (msg.value < requiredFee) {
            throw;
        }
        
        // Update timestamp state for future fee calculations
        lastCreationTime[msg.sender] = block.timestamp;
        
        // Pass along remaining ether after fee to the constructor
        uint constructorValue = msg.value - requiredFee;
        address newBOPAddr = (new BurnableOpenPayment).value(constructorValue)(payer, payerString, commitThreshold, defaultAction, defaultTimeoutLength);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        NewBOP(newBOPAddr);
        return newBOPAddr;
    }
}