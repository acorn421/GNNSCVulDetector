/*
 * ===== SmartInject Injection Details =====
 * Function      : approve
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the spender address after the allowance state is updated. The vulnerability leverages the existing tokenRecipient interface to create a callback mechanism that allows the spender to re-enter the contract during the approval process.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `tokenRecipient(_spender).receiveApproval()` after the allowance state is set
 * 2. Used try-catch to handle potential callback failures while preserving the approval
 * 3. The external call occurs after the state modification, violating the Checks-Effects-Interactions pattern
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: User calls approve() with a malicious spender contract
 * - The malicious spender's receiveApproval() callback is triggered, which can:
 *   - Call transferFrom() to immediately drain approved tokens
 *   - Call approve() again to modify allowances for other addresses
 *   - Set up state for future exploitation in subsequent transactions
 * - **Transaction 2+**: The malicious contract can leverage the persistent allowance state across multiple transactions to:
 *   - Perform complex multi-step token manipulations
 *   - Coordinate with other malicious contracts using the persistent allowance state
 *   - Execute time-delayed attacks that span multiple blocks
 * 
 * **Why Multi-Transaction Nature is Critical:**
 * - The allowance state persists between transactions, enabling complex attack vectors
 * - Malicious contracts can use the callback to set up state for future exploitation
 * - The vulnerability allows for sophisticated attacks that require coordination between multiple function calls
 * - Attackers can leverage the persistent allowance state to perform multi-step token theft or manipulation
 * - The reentrancy enables immediate token drainage while maintaining the approved allowance for future use
 * 
 * This creates a realistic vulnerability pattern similar to those found in production DeFi protocols where approval callbacks have been exploited for complex multi-transaction attacks.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract FoundGameCoin {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals;
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
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function FoundGameCoin(
        uint256 initialSupply,
        string tokenName,
	uint8 decimalUnits,
        string tokenSymbol
    ) public {
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
     * Send `_value` tokens to `_to` on behalf of `_from`
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
     * Allows `_spender` to spend no more than `_value` tokens on your behalf
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // VULNERABILITY: External call to spender after state update
        // This creates a reentrancy vector where the spender can call back
        // into the contract before the transaction completes
        if (_spender != address(0) && isContract(_spender)) {
            tokenRecipient(_spender).receiveApproval(msg.sender, _value, this, "");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }

    // Helper for contract check in <=0.4.16
    function isContract(address _addr) internal constant returns (bool) {
        uint size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }

    /**
     * Set allowance for other address and notify
     *
     * Allows `_spender` to spend no more than `_value` tokens on your behalf, and then ping the contract about it
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
