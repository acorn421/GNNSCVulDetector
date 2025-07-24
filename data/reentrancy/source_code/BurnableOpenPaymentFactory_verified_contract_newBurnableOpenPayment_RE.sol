/*
 * ===== SmartInject Injection Details =====
 * Function      : newBurnableOpenPayment
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
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: Introduced tracking mappings for deployment fees and counts that persist across transactions
 * 2. **Fee Calculation Logic**: Fees are calculated based on accumulated deployment counts from previous transactions
 * 3. **External Call Before State Updates**: Added a vulnerable external call to the payer address before updating critical state variables
 * 4. **State Update After External Call**: Moved state updates (fee tracking, deployment counts) to occur AFTER the external call
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * **Transaction 1 - Initial Setup:**
 * - Attacker deploys first contract normally (deploymentCounts[attacker] = 0, so no fee)
 * - State gets updated: deploymentCounts[attacker] = 1
 * 
 * **Transaction 2 - Reentrancy Attack:**
 * - Attacker calls newBurnableOpenPayment again with malicious payer contract
 * - Function calculates fee based on deploymentCounts[attacker] = 1
 * - External call to malicious payer contract triggers reentrancy
 * - During reentrancy, attacker can call newBurnableOpenPayment again before state updates
 * - Since state hasn't been updated yet, deploymentCounts is still 1, allowing bypass of higher fees
 * - Attacker can deploy multiple contracts while paying minimal fees
 * 
 * **Transaction 3+ - Continued Exploitation:**
 * - Attacker continues exploiting the corrupted state across multiple transactions
 * - Each reentrancy allows deployment of contracts without proper fee accounting
 * - State becomes increasingly inconsistent with actual deployments
 * 
 * **Why Multi-Transaction Requirement:**
 * - Initial transaction needed to establish non-zero deployment count
 * - Subsequent transactions exploit the accumulated state inconsistencies
 * - The vulnerability leverages state persistence between transactions
 * - Single transaction exploitation impossible due to state dependency on previous deployments
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
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint) public deploymentFees;
mapping(address => uint) public deploymentCounts;
uint public totalDeployments;
uint public feeRate = 1000; // 0.001 ETH per deployment
bool public feeCollectionEnabled = true;

// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
function newBurnableOpenPayment(address payer, string payerString, uint commitThreshold, BurnableOpenPayment.DefaultAction defaultAction, uint defaultTimeoutLength)
    public
    payable
    returns (address) {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Calculate deployment fee based on accumulated state
        uint deploymentFee = 0;
        if (feeCollectionEnabled && deploymentCounts[msg.sender] > 0) {
            deploymentFee = feeRate * deploymentCounts[msg.sender];
        }
        
        // Ensure sufficient payment for fee
        if (msg.value < deploymentFee) {
            throw;
        }
        
        // External call to payer before state updates - VULNERABILITY
        if (deploymentFee > 0) {
            bool success = payer.call.value(deploymentFee)("");
            if (!success) {
                throw;
            }
        }
        
        // State updates occur AFTER external call - CRITICAL VULNERABILITY
        deploymentFees[msg.sender] += deploymentFee;
        deploymentCounts[msg.sender] += 1;
        totalDeployments += 1;
        
        // Pass remaining ether to constructor
        uint remainingValue = msg.value - deploymentFee;
        address newBOPAddr = (new BurnableOpenPayment).value(remainingValue)(payer, payerString, commitThreshold, defaultAction, defaultTimeoutLength);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        NewBOP(newBOPAddr);
        return newBOPAddr;
    }
}