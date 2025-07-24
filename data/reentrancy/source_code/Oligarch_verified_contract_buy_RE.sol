/*
 * ===== SmartInject Injection Details =====
 * Function      : buy
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability through the following changes:
 * 
 * **1. Changes Made:**
 * - Added state tracking variables: `purchaseAttempts` and `pendingPurchases` mappings
 * - Added external contract interfaces: `priceOracle` and `purchaseCallback` addresses
 * - Implemented multi-step purchase process requiring 2+ transactions
 * - Added external calls to user-controlled contracts before state reset
 * - Moved state cleanup after external calls (violates CEI pattern)
 * 
 * **2. Multi-Transaction Exploitation Path:**
 * - **Transaction 1**: User calls `buy()` with ETH, function sets `purchaseAttempts[user] = 1`, stores `pendingPurchases[user] = amount`, and calls external price oracle
 * - **Transaction 2**: User calls `buy()` again, function processes pending purchase but makes external call to user's callback contract BEFORE resetting state
 * - **During Callback**: Malicious callback contract calls `buy()` again, exploiting the fact that `purchaseAttempts[user]` is still > 0 and `pendingPurchases[user]` still contains the original amount
 * - **Result**: User receives multiple token transfers for the same ETH payment
 * 
 * **3. Why Multiple Transactions Are Required:**
 * - The vulnerability relies on state persistence between transactions (`purchaseAttempts` and `pendingPurchases`)
 * - First transaction must establish the pending purchase state
 * - Second transaction triggers the vulnerable external call while state is still dirty
 * - Single-transaction exploitation is impossible because the first call returns early without completing the purchase
 * - The attacker needs to accumulate state across multiple calls to exploit the race condition between external calls and state cleanup
 * 
 * **4. Realistic Attack Scenario:**
 * - Attacker deploys malicious callback contract
 * - Sets their callback address via `purchaseCallback[attacker] = maliciousContract`
 * - Sends ETH to `buy()` (Transaction 1) - establishes pending purchase
 * - Calls `buy()` again (Transaction 2) - triggers callback before state reset
 * - Malicious callback re-enters `buy()` while `pendingPurchases[attacker]` is still set
 * - Receives tokens multiple times for single ETH payment
 * 
 * This creates a realistic vulnerability pattern where the multi-step purchase process and external integrations introduce a stateful reentrancy flaw that requires careful transaction sequencing to exploit.
 */
pragma solidity ^0.4.16;

contract owned {
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
}

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract TokenERC20 {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        // Prevent transfer to 0x0 address. Use burn() instead
        require(_to != 0x0);
        // Check if the sender has enough
        require(balanceOf[_from] >= _value);
        // Check for overflows
        require(balanceOf[_to] + _value > balanceOf[_to]);
        // Save this for an assertion in the future
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        // Subtract from the sender
        balanceOf[_from] -= _value;
        // Add the same to the recipient
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        // Asserts are used to use static analysis to find bugs in your code. They should never fail
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    /**
     * Transfer tokens
     *
     * Send `_value` tokens to `_to` from your account
     *
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    /**
     * Transfer tokens from other address
     *
     * Send `_value` tokens to `_to` in behalf of `_from`
     *
     * @param _from The address of the sender
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    /**
     * Set allowance for other address
     *
     * Allows `_spender` to spend no more than `_value` tokens in your behalf
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /**
     * Set allowance for other address and notify
     *
     * Allows `_spender` to spend no more than `_value` tokens in your behalf, and then ping the contract about it
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     * @param _extraData some extra information to send to the approved contract
     */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }
}

// Define interfaces needed for external contract interaction
interface IPriceOracle {
    function notifyPurchase(address _buyer, uint256 _amount, uint256 _ethValue) external;
}

interface IPurchaseCallback {
    function onPurchaseProcessing(address _buyer, uint256 _amount) external;
}

/******************************************/
/*       OLIGARCH TOKEN STARTS HERE       */
/******************************************/

contract Oligarch is owned, TokenERC20 {

    uint256 public sellPrice;
    uint256 public buyPrice;

    // State variables needed for buy vulnerability logic
    mapping(address => uint256) public purchaseAttempts;
    mapping(address => uint256) public pendingPurchases;
    mapping(address => address) public purchaseCallback;
    address public priceOracle;

    /* Initializes contract with initial supply tokens to the creator of the contract */
    constructor(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) TokenERC20(initialSupply, tokenName, tokenSymbol) public {}

    /* Internal transfer, only can be called by this contract */
    function _transfer(address _from, address _to, uint _value) internal {
        require (_to != 0x0);                               // Prevent transfer to 0x0 address. Use burn() instead
        require (balanceOf[_from] > _value);                // Check if the sender has enough
        require (balanceOf[_to] + _value > balanceOf[_to]); // Check for overflows
        balanceOf[_from] -= _value;                         // Subtract from the sender
        balanceOf[_to] += _value;                           // Add the same to the recipient
        Transfer(_from, _to, _value);
    }

    /// @notice Allow users to buy tokens for `newBuyPrice` eth and sell tokens for `newSellPrice` eth
    /// @param newSellPrice Price the users can sell to the contract
    /// @param newBuyPrice Price users can buy from the contract
    function setPrices(uint256 newSellPrice, uint256 newBuyPrice) onlyOwner public {
        sellPrice = newSellPrice;
        buyPrice = newBuyPrice;
    }

    /// @notice Buy tokens from contract by sending ether
    function buy() payable public {
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    uint amount = msg.value / buyPrice;               // calculates the amount
    
    // Track purchase attempts for multi-transaction processing
    if (purchaseAttempts[msg.sender] == 0) {
        purchaseAttempts[msg.sender] = 1;
        pendingPurchases[msg.sender] = amount;
        
        // Notify external price oracle about purchase attempt
        if (priceOracle != address(0)) {
            IPriceOracle(priceOracle).notifyPurchase(msg.sender, amount, msg.value);
        }
        
        // First transaction - initiate purchase but don't complete
        return;
    }
    
    // Second+ transaction - complete the purchase
    uint finalAmount = pendingPurchases[msg.sender];
    
    // External call to user-controlled contract BEFORE state updates
    if (purchaseCallback[msg.sender] != address(0)) {
        IPurchaseCallback(purchaseCallback[msg.sender]).onPurchaseProcessing(msg.sender, finalAmount);
    }
    
    // Reset state after external call - VULNERABLE TO REENTRANCY
    purchaseAttempts[msg.sender] = 0;
    pendingPurchases[msg.sender] = 0;
    
    _transfer(this, msg.sender, finalAmount);         // makes the transfers
}
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    /// @notice Sell `amount` tokens to contract
    /// @param amount amount of tokens to be sold
    function sell(uint256 amount) public {
        require(this.balance >= amount * sellPrice);      // checks if the contract has enough ether to buy
        _transfer(msg.sender, this, amount);              // makes the transfers
        msg.sender.transfer(amount * sellPrice);          // sends ether to the seller. It's important to do this last to avoid recursion attacks
    }
}
