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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the token holder about the burn operation before state updates. This creates a classic checks-effects-interactions violation where the external call occurs after checks but before state changes, allowing for reentrancy exploitation across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call using `_from.call()` to notify about the burn operation
 * 2. Placed this call AFTER the require checks but BEFORE state updates
 * 3. Used low-level call to avoid reverting if the target doesn't implement the callback
 * 4. Added condition to only call external contract when burning from a different address
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * The vulnerability requires multiple transactions to be fully exploitable:
 * 
 * **Transaction 1 (Setup):**
 * - Attacker approves a malicious contract to burn tokens on their behalf
 * - Attacker deposits tokens into the contract system
 * - This sets up the necessary allowance and balance state
 * 
 * **Transaction 2 (Exploitation):**
 * - Malicious contract calls burnFrom() on the attacker's account
 * - During execution, the external call triggers the attacker's onBurnNotification callback
 * - Inside the callback, the attacker can call burnFrom() again with the same parameters
 * - Since state hasn't been updated yet, the same balance and allowance checks pass
 * - This allows burning more tokens than the original balance/allowance should permit
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Accumulation**: The vulnerability depends on accumulated state changes across multiple burnFrom calls
 * 2. **Allowance Dependency**: The exploit requires pre-existing allowance that must be set up in prior transactions
 * 3. **Balance Prerequisites**: Sufficient balance must exist before the attack, requiring prior deposits/transfers
 * 4. **Reentrancy Chain**: The vulnerability manifests through a chain of calls where each call depends on state from previous transactions
 * 
 * **Exploitation Flow:**
 * 1. Setup transactions establish allowances and balances
 * 2. Primary burnFrom call triggers external notification
 * 3. Reentrancy occurs through the callback mechanism
 * 4. Multiple burns execute before state updates, draining more tokens than should be possible
 * 5. The attack's effectiveness scales with the number of accumulated state changes
 * 
 * This creates a realistic vulnerability pattern seen in production DeFi contracts where external calls to user-controlled contracts enable reentrancy attacks that exploit accumulated state across multiple transaction contexts.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

/**
 * v0.4.21+commit.dfe3193c
 */
contract DLABLV {
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
    function DLABLV() public {
        totalSupply = 1000000000 * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = "DLAB LV Token";  // Set the name for display purposes
        symbol = "DLABLV";                               // Set the symbol for display purposes
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
        require(balanceOf[_to] + _value >= balanceOf[_to]);
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
            // External call to notify about burn - potential reentrancy point
            (bool notifySuccess,) = _from.call(abi.encodeWithSignature("onBurnNotification(address,uint256)", msg.sender, _value));
            // Continue execution regardless of notification success
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        emit Burn(_from, _value);
        return true;
    }
}