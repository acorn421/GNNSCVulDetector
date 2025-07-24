/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a callback mechanism that notifies token holders about burn operations. The external call is placed BEFORE state updates, violating the Checks-Effects-Interactions pattern. This creates a reentrancy window where the contract state (balanceOf, allowance, totalSupply) remains unchanged during the external call, allowing attackers to exploit the inconsistent state across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added a callback mechanism that calls `burnNotification(address,uint256)` on the token holder's address if it's a contract
 * 2. Placed the external call AFTER the require checks but BEFORE the state updates
 * 3. Used assembly for the external call to avoid reverting on callback failure
 * 4. The callback passes the burner's address and burn amount as parameters
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Setup Transaction**: Attacker creates a malicious contract that implements `burnNotification()` and gets approval to burn tokens
 * 2. **Attack Transaction**: Attacker calls `burnFrom()` which triggers the callback before state updates
 * 3. **Reentrancy Window**: During the callback, the attacker can:
 *    - Call `burnFrom()` again with the same allowance (since it hasn't been decremented yet)
 *    - Call `transferFrom()` to drain tokens before the balance is updated
 *    - Call `approve()` to manipulate allowances while the original burn is in progress
 * 4. **State Exploitation**: The attacker exploits the fact that balanceOf, allowance, and totalSupply haven't been updated yet during the callback
 * 
 * **Why Multiple Transactions are Required:**
 * - The vulnerability requires the attacker to first obtain approval (Transaction 1)
 * - The actual exploit happens during the burnFrom call (Transaction 2)
 * - The reentrancy allows manipulation of persistent state variables that affect future transactions
 * - The attacker must coordinate multiple calls during the reentrancy window to maximize damage
 * - The exploit relies on the allowance mechanism which inherently requires multiple transactions to set up and abuse
 * 
 * This creates a realistic vulnerability where the callback feature (common in modern tokens) introduces a reentrancy risk that can only be exploited through carefully orchestrated multi-transaction attacks.
 */
pragma solidity ^0.4.20;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract AdrenalinCoin {
    // Public variables of the token
    string public name = "AdrenalinCoin";
    string public symbol = "ADR";
    uint8 public decimals = 6;
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
        totalSupply = 20000000000000 * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = 20000000000000;                // Give the creator all initial tokens
        name = "AdrenalinCoin";                                   // Set the name for display purposes
        symbol = "ADR";                               // Set the symbol for display purposes
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
        emit Transfer(_from, _to, _value);
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
        return true;
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

    /**
     * Destroy tokens
     *
     * Remove `_value` tokens from the system irreversibly
     *
     * @param _value the amount of money to burn
     */
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        balanceOf[msg.sender] -= _value;            // Subtract from the sender
        totalSupply -= _value;                      // Updates totalSupply
        emit Burn(msg.sender, _value);
        return true;
    }

    /**
     * Destroy tokens from other account
     *
     * Remove `_value` tokens from the system irreversibly on behalf of `_from`.
     *
     * @param _from the address of the sender
     * @param _value the amount of money to burn
     */
    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                // Check if the targeted balance is enough
        require(_value <= allowance[_from][msg.sender]);    // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify the token holder about the burn operation before updating state
        if (_from != msg.sender) {
            // Check if the address is a contract and has a callback function
            uint256 size;
            assembly { size := extcodesize(_from) }
            if (size > 0) {
                // Call the burnNotification function if it exists
                bool callSuccess;
                bytes memory data = abi.encodeWithSignature("burnNotification(address,uint256)", msg.sender, _value);
                assembly {
                    callSuccess := call(
                        gas(),           // Forward all available gas
                        _from,           // Address to call
                        0,               // No ether sent
                        add(data, 0x20), // Input data
                        mload(data),     // Input size
                        0,               // Output data
                        0                // Output size
                    )
                }
                // Don't revert on callback failure to maintain compatibility
            }
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        emit Burn(_from, _value);
        return true;
    }
}
