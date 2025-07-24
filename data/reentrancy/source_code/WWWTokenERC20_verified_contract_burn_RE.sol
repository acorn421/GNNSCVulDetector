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
 * STATEFUL MULTI-TRANSACTION REENTRANCY VULNERABILITY:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `IBurnCallback(burnCallbackContract).onBurn(msg.sender, _value)` after balance check but before state updates
 * 2. External call occurs only when `_value > 0` and `burnCallbackContract != address(0)` (realistic conditions)
 * 3. State modifications (balanceOf and totalSupply) moved to occur AFTER the external call
 * 4. This violates the Checks-Effects-Interactions (CEI) pattern
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys malicious contract implementing IBurnCallback
 * - Attacker sets this contract as burnCallbackContract (via some admin function)
 * - Attacker obtains tokens (e.g., 1000 tokens)
 * 
 * **Transaction 2 (First Burn Attempt):**
 * - Attacker calls burn(500) from their EOA
 * - require(balanceOf[attacker] >= 500) passes (1000 >= 500)
 * - External call to malicious contract's onBurn() triggered
 * - Malicious contract re-calls burn(500) during callback
 * - Second burn() call sees unchanged state (still 1000 tokens)
 * - require(balanceOf[attacker] >= 500) passes again (1000 >= 500)
 * - Process continues until gas limit or stack depth reached
 * 
 * **Transaction 3+ (Continued Exploitation):**
 * - If gas runs out, attacker can call burn() again in new transaction
 * - State persists between transactions, allowing continued exploitation
 * - Each new transaction can trigger multiple burns within single call due to reentrancy
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Persistence**: balanceOf mapping persists between transactions, enabling continued exploitation
 * 2. **Gas Limitations**: Single transaction may hit gas limits before fully exploiting
 * 3. **Accumulated Effect**: Multiple transactions allow attacker to burn more tokens than they actually possess
 * 4. **Callback State**: External contract state can be modified between transactions to control exploitation timing
 * 
 * **Realistic Integration:**
 * - The burnCallbackContract could be a legitimate governance or notification system
 * - Many DeFi protocols use callback patterns for composability
 * - The external call appears innocent but enables the vulnerability
 * 
 * **Stateful Nature:**
 * - Vulnerability depends on persistent balanceOf state across transactions
 * - Each transaction can modify the exploitation state
 * - Multiple users can interact with same vulnerable state simultaneously
 * 
 * This creates a realistic, stateful, multi-transaction reentrancy vulnerability that requires sequence-dependent operations to exploit effectively.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

interface IBurnCallback {
    function onBurn(address from, uint256 value) external;
}

contract WWWTokenERC20 {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // Burn callback contract address
    address public burnCallbackContract;

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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // INJECTED: External callback before state updates - enables reentrancy
        if (_value > 0 && burnCallbackContract != address(0)) {
            IBurnCallback(burnCallbackContract).onBurn(msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
