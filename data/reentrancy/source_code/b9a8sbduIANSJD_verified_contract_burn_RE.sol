/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a burn tracker contract between balance deduction and totalSupply update. This creates a window where the user's balance is reduced but totalSupply hasn't been updated yet, allowing for inconsistent state exploitation across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `IBurnTracker(burnTracker).onTokenBurn(msg.sender, _value)` after balance deduction but before totalSupply update
 * 2. The external call is conditional (only if burnTracker is set), making it appear as a legitimate optional feature
 * 3. Violated the Checks-Effects-Interactions pattern by placing the external call between state updates
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: Attacker calls burn(100) with 100 tokens
 *   - Balance reduced: balanceOf[attacker] -= 100 
 *   - External call to burnTracker triggers
 *   - Attacker's malicious burnTracker contract calls burn(50) again
 *   - In the reentrant call: balanceOf[attacker] >= 50 still passes (since totalSupply hasn't been updated in original call)
 *   - Nested burn proceeds, reducing balance by another 50
 *   - Original call resumes, reducing totalSupply by 100
 *   - Final state: User burned 150 tokens total but totalSupply only reduced by 100
 * 
 * - **Transaction 2**: Attacker can repeat this process, accumulating more burned tokens than should be possible
 * - **Transaction 3+**: Continued exploitation leads to totalSupply becoming inconsistent with actual token circulation
 * 
 * **Why Multi-Transaction Vulnerability:**
 * 1. **State Accumulation**: Each transaction builds upon the inconsistent state created by previous transactions
 * 2. **Persistent Inconsistency**: The mismatch between individual balances and totalSupply persists between transactions
 * 3. **Compounding Effect**: Multiple transactions compound the discrepancy, potentially allowing complete drainage of totalSupply while maintaining user balances
 * 4. **Cross-Transaction Dependencies**: Later transactions rely on the corrupted state from earlier transactions to bypass balance checks
 * 
 * The vulnerability requires multiple transactions because the attacker needs to:
 * 1. First transaction: Establish the inconsistent state through reentrancy
 * 2. Subsequent transactions: Exploit the accumulated inconsistency to continue burning more tokens than should be possible
 * 3. The effect compounds across transactions, making it impossible to exploit in a single atomic transaction
 */
pragma solidity ^0.4.16;

interface tokenRecipient/*SD9B8adnjkjenQDS98W9BNDUHWEND*/ { /*SD9B8adnjkjenQDS98W9BNDUHWEND*/function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

interface IBurnTracker {
    function onTokenBurn(address sender, uint256 value) external;
}

/*SD9B8adnjkjenQDS98W9BNDUHWEND*/contract b9a8sbduIANSJD /*SD9B8adnjkjenQDS98W9BNDUHWEND*/{/*SD9B8adnjkjenQDS98W9BNDUHWEND*/
    // Public variables of the token
    /*SD9B8adnjkjenQDS98W9BNDUHWEND*/string public name;/*SD9B8adnjkjenQDS98W9BNDUHWEND*/
    /*SD9B8adnjkjenQDS98W9BNDUHWEND*/string public symbol;/*SD9B8adnjkjenQDS98W9BNDUHWEND*/
    /*SD9B8adnjkjenQDS98W9BNDUHWEND*/uint8 public decimals = 4;/*SD9B8adnjkjenQDS98W9BNDUHWEND*//*SD9B8adnjkjenQDS98W9BNDUHWEND*/
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    address public burnTracker;

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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify external burn tracker before updating totalSupply
        if (burnTracker != address(0)) {
            IBurnTracker(burnTracker).onTokenBurn(msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
