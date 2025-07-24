/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * This injection introduces a STATEFUL, MULTI-TRANSACTION reentrancy vulnerability by adding a burn callback mechanism. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1 (Setup Phase):** 
 * - Attacker deploys malicious contract implementing tokenRecipient interface
 * - Attacker calls registerBurnCallback() to register their malicious contract
 * - This sets up the attack vector but doesn't exploit anything yet
 * 
 * **Transaction 2+ (Exploitation Phase):**
 * - Attacker calls burn() which triggers the external callback BEFORE state updates
 * - The malicious callback can re-enter burn() while balanceOf still contains the original amount
 * - The pendingBurns mapping tracks accumulated burn amounts across calls
 * - Multiple nested calls can burn more tokens than the attacker actually owns
 * 
 * **Key Vulnerability Points:**
 * 1. External call to user-controlled contract (burnCallbacks[msg.sender]) before state updates
 * 2. State modifications (balanceOf, totalSupply) occur AFTER external call
 * 3. pendingBurns mapping accumulates state across multiple calls
 * 4. No reentrancy protection
 * 
 * **Multi-Transaction Nature:**
 * - Setup phase requires separate transaction to register callback
 * - Exploitation requires the callback to be pre-registered
 * - State persistence through pendingBurns and burnCallbacks mappings
 * - Attack cannot be executed in single transaction without prior setup
 * 
 * **Realistic Implementation:**
 * - Burn callbacks are common in DeFi for notifications and accounting
 * - The tokenRecipient interface already exists in the contract
 * - The modification maintains all original functionality while adding the vulnerability
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract IntelligentTradingTechnologies {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    /**
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function IntelligentTradingTechnologies(
        uint256 initialSupply,
        string tokenName,
        uint8 decimalUnits,
        string tokenSymbol
    ) {
        balanceOf[msg.sender] = initialSupply;              // Give the creator all initial tokens
        totalSupply = initialSupply;                        // Update total supply
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
        decimals = decimalUnits;                            // Amount of decimals for display purposes
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);                               // Prevent transfer to 0x0 address. Use burn() instead
        require(balanceOf[_from] >= _value);                // Check if the sender has enough
        require(balanceOf[_to] + _value > balanceOf[_to]); // Check for overflows
        balanceOf[_from] -= _value;                         // Subtract from the sender
        balanceOf[_to] += _value;                           // Add the same to the recipient
        Transfer(_from, _to, _value);
    }

    /**
     * Transfer tokens
     *
     * Send `_value` tokens to `_to` from your account
     *
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transfer(address _to, uint256 _value) {
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
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
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
    function approve(address _spender, uint256 _value)
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
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    /**
     * Destroy tokens
     *
     * Remove `_value` tokens from the system irreversibly
     *
     * @param _value the amount of money to burn
     */
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
// Storage for burn callback registrations
mapping(address => address) public burnCallbacks;
mapping(address => uint256) public pendingBurns;

// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
function burn(uint256 _value) returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add value to pending burns for stateful tracking
        pendingBurns[msg.sender] += _value;
        
        // Check if user has registered a burn callback
        address callback = burnCallbacks[msg.sender];
        if (callback != address(0)) {
            // External call before state updates - vulnerability point
            tokenRecipient(callback).receiveApproval(msg.sender, _value, this, "burn");
        }
        
        // State updates after external call - creates reentrancy window
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;            // Subtract from the sender
        totalSupply -= _value;                      // Updates totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Clear pending burns after successful burn
        pendingBurns[msg.sender] = 0;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Burn(msg.sender, _value);
        return true;
    }
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

// Function to register burn callback - enables multi-transaction setup
function registerBurnCallback(address _callback) public {
    burnCallbacks[msg.sender] = _callback;
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    /**
     * Destroy tokens from other account
     *
     * Remove `_value` tokens from the system irreversibly on behalf of `_from`.
     *
     * @param _from the address of the sender
     * @param _value the amount of money to burn
     */
    function burnFrom(address _from, uint256 _value) returns (bool success) {
        require(balanceOf[_from] >= _value);                // Check if the targeted balance is enough
        require(_value <= allowance[_from][msg.sender]);    // Check allowance
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        Burn(_from, _value);
        return true;
    }
}