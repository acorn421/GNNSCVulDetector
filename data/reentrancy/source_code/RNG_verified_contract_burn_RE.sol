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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback mechanism before state updates. The vulnerability requires multiple transactions to exploit because:
 * 
 * 1. **Multi-Transaction Exploitation Pattern**:
 *    - Transaction 1: Attacker calls burn() → callback stores attack state but doesn't complete exploit due to unchanged balanceOf
 *    - Transaction 2: Attacker calls burn() again → callback detects accumulated state from previous call → exploits inconsistent state where balance check passes but state updates haven't occurred yet
 * 
 * 2. **State Persistence Between Transactions**:
 *    - The attacker's contract can store state between transactions (e.g., tracking multiple burn attempts)
 *    - balanceOf remains unchanged during the external call, allowing repeated exploitation across transactions
 *    - Each transaction's callback can build upon state from previous transactions
 * 
 * 3. **Realistic Attack Vector**:
 *    - Malicious contract implements IBurnCallback interface
 *    - In onBurn(), it can re-enter burn() or other functions while balanceOf hasn't been updated
 *    - Across multiple transactions, it can accumulate more burns than the actual balance should allow
 *    - The vulnerability exploits the time gap between balance check and balance update
 * 
 * 4. **Why Multiple Transactions Are Required**:
 *    - Single transaction reentrancy would be limited by gas and call stack
 *    - Multi-transaction allows unlimited re-entries with fresh gas and stack
 *    - State accumulation across transactions enables more sophisticated attacks
 *    - Attacker can coordinate complex multi-step exploits that wouldn't fit in single transaction
 * 
 * This creates a realistic vulnerability where DeFi protocols might implement burn callbacks for legitimate purposes (staking rewards, accounting updates) but create a multi-transaction reentrancy attack surface.
 */
pragma solidity ^0.4.21;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

interface IBurnCallback {
    function onBurn(uint256 _value) external;
}

contract RNG {
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
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function RNG(
    ) public {
        totalSupply = 1000000000000000000000000000;                             // Total supply with the decimal amount
        balanceOf[msg.sender] = 1000000000000000000000000000;                   // All initial tokens
        name = "Ringside";                                                      // The name for display purposes
        symbol = "RNG";                                                         // The symbol for display purposes
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External callback to notify about burn operation (realistic DeFi pattern)
        if (msg.sender != address(0)) {
            // Simulate the external call, without try/catch (not available in 0.4.21)
            // and without using .code.length (not available in 0.4.21)
            // Instead, we allow a low-level call to mimic a callback
            IBurnCallback(msg.sender).onBurn(_value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;            // Subtract from the sender
        totalSupply -= _value;                      // Updates totalSupply
        Burn(msg.sender, _value);
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
        Burn(_from, _value);
        return true;
    }
}
