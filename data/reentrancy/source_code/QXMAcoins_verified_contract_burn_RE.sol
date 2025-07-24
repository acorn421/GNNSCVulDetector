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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a burn callback mechanism. The vulnerability requires:
 * 
 * 1. **Transaction 1**: User calls `registerBurnCallback()` to register a malicious callback contract
 * 2. **Transaction 2**: User calls `burn()` which triggers the callback BEFORE state updates
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - Transaction 1: Attacker registers malicious callback via `registerBurnCallback()`
 * - Transaction 2: Attacker calls `burn(100)` 
 * - During callback execution: Malicious contract calls `burn(100)` again
 * - First burn call: Checks balance (200 tokens), calls callback
 * - Callback re-enters: Checks same balance (200 tokens), proceeds with second burn
 * - State updates happen: First burn completes, reduces balance to 100 and totalSupply by 100
 * - Second burn completes: Reduces balance to 0 and totalSupply by another 100
 * - Result: User burned 200 tokens but totalSupply was reduced by 200, creating accounting inconsistency
 * 
 * **Why Multi-Transaction is Required:**
 * - The callback registration in `burnCallbacks` mapping persists between transactions
 * - The vulnerability depends on having a registered callback from a previous transaction
 * - Cannot be exploited in a single transaction without prior callback registration
 * - The persistent state (registered callback) enables the reentrancy attack in subsequent transactions
 * 
 * **Realistic Implementation:**
 * - Burn callbacks are common in DeFi for notifications and integrations
 * - The callback pattern appears legitimate for token burn events
 * - The vulnerability is subtle - external call before state updates violates CEI pattern
 * - State persistence through the `burnCallbacks` mapping makes this a stateful vulnerability
 */
pragma solidity ^0.4.17;

contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

// Define interface for burn callback
interface IBurnCallback {
    function onTokenBurn(address from, uint256 value) external;
}

contract QXMAcoins{
    /* Public variables of the token */
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    constructor() public {
        balanceOf[msg.sender] = 300000000000000000; // Give the creator all initial tokens
        totalSupply = 300000000000000000;                        // Update total supply
        name = "Quanxin mining Alliance";                                   // Set the name for display purposes
        symbol = "QXMA";                             // Set the symbol for display purposes
        decimals = 8;                            // Amount of decimals for display purposes
    }

    /* Internal transfer, only can be called by this contract */
    function _transfer(address _from, address _to, uint _value) internal {
        require (_to != 0x0);                               // Prevent transfer to 0x0 address. Use burn() instead
        require (balanceOf[_from] >= _value);                // Check if the sender has enough
        require (balanceOf[_to] + _value > balanceOf[_to]); // Check for overflows
        balanceOf[_from] -= _value;                         // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        Transfer(_from, _to, _value);
    }

    /// @notice Send `_value` tokens to `_to` from your account
    /// @param _to The address of the recipient
    /// @param _value the amount to send
    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    /// @notice Send `_value` tokens to `_to` in behalf of `_from`
    /// @param _from The address of the sender
    /// @param _to The address of the recipient
    /// @param _value the amount to send
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require (_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    /// @notice Allows `_spender` to spend no more than `_value` tokens in your behalf
    /// @param _spender The address authorized to spend
    /// @param _value the max amount they can spend
    function approve(address _spender, uint256 _value)
        public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /// @notice Allows `_spender` to spend no more than `_value` tokens in your behalf, and then ping the contract about it
    /// @param _spender The address authorized to spend
    /// @param _value the max amount they can spend
    /// @param _extraData some extra information to send to the approved contract
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    /// @notice Remove `_value` tokens from the system irreversibly
    /// @param _value the amount of money to burn
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => address) public burnCallbacks;  // Add this state variable to contract

    function burn(uint256 _value) public returns (bool success) {
        require (balanceOf[msg.sender] >= _value);            // Check if the sender has enough
        // External call before state updates - vulnerability injection point
        if (burnCallbacks[msg.sender] != address(0)) {
            // Call user-registered callback contract before burning
            IBurnCallback(burnCallbacks[msg.sender]).onTokenBurn(msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Additional function to register burn callbacks
    function registerBurnCallback(address _callback) public {
        burnCallbacks[msg.sender] = _callback;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                // Check if the targeted balance is enough
        require(_value <= allowance[_from][msg.sender]);    // Check allowance
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        Burn(_from, _value);
        return true;
    }

   function getBalance(address addr) public constant   returns(uint256) {
        return balanceOf[addr];
    }

}