/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract after state modifications. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added storage of original allowance value before modification
 * 2. Added external call to recipient contract using low-level call() after state changes
 * 3. The external call includes sensitive state information (original allowance) that can be exploited
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker deploys malicious contract and gets approval from victim for large allowance
 * 2. **Transaction 2**: Attacker calls transferFrom() which triggers the external call to malicious contract
 * 3. **During Transaction 2**: Malicious contract's onTokenReceived() function re-enters transferFrom() before the original call completes
 * 4. **State Exploitation**: The allowance state persists between calls, allowing the attacker to drain more tokens than originally approved by leveraging the state changes from previous transactions
 * 
 * **Why Multi-Transaction Dependency is Critical:**
 * - The vulnerability cannot be exploited in a single atomic transaction because it requires pre-existing allowance state from previous approve() calls
 * - The attacker must first establish allowance state in one transaction, then exploit it in subsequent transferFrom() calls
 * - The external call passes originalAllowance value, which represents state from before the current transaction's modifications, creating temporal state inconsistencies that can be exploited across multiple calls
 * - The reentrancy opportunity depends on the accumulated state changes from the sequence of approve() → transferFrom() → re-entrant transferFrom() calls
 * 
 * This creates a realistic vulnerability where the attacker can drain more tokens than intended by exploiting the state persistence between transactions and the reentrancy opportunity provided by the external call.
 */
pragma solidity ^0.4.17;

contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

 

contract QXMAcoins {
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
        emit Transfer(_from, _to, _value);
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Store original allowance for potential notification
        uint256 originalAllowance = allowance[_from][msg.sender];
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient if it's a contract - VULNERABILITY: External call after state changes
        uint length;
        assembly {
            length := extcodesize(_to)
        }
        if (length > 0) {
            // Call recipient contract to notify about received tokens
            // 'call' must use old-style, since this is 0.4.17
            _to.call(
                bytes4(keccak256("onTokenReceived(address,address,uint256,uint256)")),
                _from, msg.sender, _value, originalAllowance
            );
            // Continue execution regardless of call success to maintain functionality
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }

    /// @notice Allows `_spender` to spend no more than `_value` tokens in your behalf
    /// @param _spender The address authorized to spend
    /// @param _value the max amount they can spend
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /// @notice Allows `_spender` to spend no more than `_value` tokens in your behalf, and then ping the contract about it
    /// @param _spender The address authorized to spend
    /// @param _value the max amount they can spend
    /// @param _extraData some extra information to send to the approved contract
    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    /// @notice Remove `_value` tokens from the system irreversibly
    /// @param _value the amount of money to burn
    function burn(uint256 _value) public returns (bool success) {
        require (balanceOf[msg.sender] >= _value);            // Check if the sender has enough
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        emit Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                // Check if the targeted balance is enough
        require(_value <= allowance[_from][msg.sender]);    // Check allowance
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        emit Burn(_from, _value);
        return true;
    }

   function getBalance(address addr) public constant returns(uint256) {
        return balanceOf[addr];
    }
    
}
