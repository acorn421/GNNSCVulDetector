/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient before state updates. 
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `_to.call()` to notify recipient contracts before updating allowance
 * 2. The call uses `onTokenReceived(address,address,uint256)` signature for recipient notification
 * 3. State updates (allowance reduction) happen AFTER the external call, violating CEI pattern
 * 4. Added check for contract code existence to make the call realistic
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1 (Setup)**: Attacker sets up allowance for a malicious contract
 * 2. **Transaction 2 (Trigger)**: Victim calls transferFrom to send tokens to attacker's contract
 * 3. **During Transaction 2**: The external call to attacker's contract triggers reentrancy
 * 4. **Reentrancy Exploitation**: Attacker's contract calls transferFrom again before allowance is reduced
 * 5. **Transaction 3+ (Drain)**: Multiple reentrant calls drain more tokens than originally approved
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires prior allowance setup (Transaction 1)  
 * - The actual exploitation happens during the transferFrom call (Transaction 2)
 * - State persistence between transactions enables the accumulated unauthorized transfers
 * - The attacker cannot set allowance and exploit in the same transaction due to different msg.sender contexts
 * - Each reentrant call within Transaction 2 creates a new execution context that depends on the persistent allowance state
 * 
 * **Exploitation Scenario:**
 * 1. Alice approves 100 tokens for Bob's contract
 * 2. Alice calls transferFrom(alice, bobContract, 100) 
 * 3. Bob's contract receives onTokenReceived callback
 * 4. Bob reentrantly calls transferFrom(alice, bobContract, 100) again
 * 5. Since allowance hasn't been reduced yet, Bob can drain 200 tokens instead of 100
 * 6. This requires the initial approval transaction and subsequent transfer transaction to be separate
 */
pragma solidity ^0.4.20;

interface tokenRecipient { 
    function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; 
}

/**
 * Base Contract of ERC20
 */
 contract TokenOfResource {
 	// Public variables of the token
    string public name;
    string public symbol;

    uint8 public decimals = 18;
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
    constructor() public {
        totalSupply = 10000000000 * 10 ** uint256(decimals);   	// Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                    // Give the creator all initial tokens

        name = 'Resource Token';                                // Set the name for display purposes
        symbol = 'RT';                                          // Set the symbol for display purposes
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
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

        // Add external call before state updates for recipient notification
        // In Solidity 0.4.x, no code property, so use extcodesize inline assembly
        uint256 size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            // Attempt to notify recipient contract - this creates reentrancy opportunity
            _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
            // Continue execution regardless of call result
        }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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
    function approve(address _spender, uint256 _value) public returns (bool success) {
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
    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
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

        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance

        totalSupply -= _value;                              // Update totalSupply

        emit Burn(_from, _value);
        return true;
    }

 }