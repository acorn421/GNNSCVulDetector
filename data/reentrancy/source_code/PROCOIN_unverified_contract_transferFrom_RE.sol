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
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call Before State Completion**: Introduced a callback mechanism `onTokenReceived` that is called on the recipient address before the internal `_transfer` is executed.
 * 
 * 2. **Vulnerable State Ordering**: The allowance is reduced immediately after the requirement check, but before the actual token transfer occurs. This creates a window where the allowance state is inconsistent with the actual token balances.
 * 
 * 3. **Callback Mechanism**: Added a check for contract code at the recipient address and calls `onTokenReceived` if it exists, allowing the recipient to execute code during the transfer process.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Setup:**
 * - Attacker deploys a malicious contract (MaliciousRecipient) 
 * - Victim approves the attacker's externally owned account (EOA) to spend 1000 tokens
 * - `allowance[victim][attackerEOA] = 1000`
 * 
 * **Transaction 2 - Initial Exploitation:**
 * - Attacker calls `transferFrom(victim, maliciousContract, 500)` from their EOA
 * - The function reduces allowance: `allowance[victim][attackerEOA] = 500`
 * - External call to `maliciousContract.onTokenReceived()` is made
 * - **REENTRANCY OCCURS**: MaliciousRecipient calls back to `transferFrom(victim, attackerEOA, 500)`
 * - The second call sees `allowance[victim][attackerEOA] = 500` (still sufficient)
 * - Second call reduces allowance: `allowance[victim][attackerEOA] = 0`
 * - Both transfers complete, but 1000 tokens were transferred using only 1000 allowance
 * 
 * **Transaction 3 - Continued Exploitation:**
 * - If the victim approves more tokens in subsequent transactions, the same pattern can be repeated
 * - The attacker can continue to exploit the reentrancy as long as new allowances are granted
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Persistence**: The allowance state persists between transactions, enabling the vulnerability to span multiple calls.
 * 
 * 2. **Approval Dependency**: The vulnerability requires prior approval transactions to set up the allowance state that gets exploited.
 * 
 * 3. **Accumulated Effect**: Each exploitation round requires the allowance to be replenished through separate approval transactions, making it a multi-transaction attack pattern.
 * 
 * 4. **Realistic Attack Vector**: Real-world scenarios often involve multiple approvals over time, making this a persistent vulnerability that can be exploited repeatedly across different transactions.
 * 
 * The vulnerability is stateful because it depends on the persistent allowance mappings and is multi-transaction because it requires the initial approval setup and can be exploited across multiple transfer attempts as new allowances are granted.
 */
pragma solidity >=0.4.22 <0.6.0;

interface tokenRecipient { 
    function receiveApproval(address _from, uint256 _value, address _token, bytes memory _extraData) external; 
}

contract PROCOIN {
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
    
    // This generates a public event on the blockchain that will notify clients
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor(
        uint256 initialSupply,
        string memory tokenName,
        string memory tokenSymbol
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
        require(_to != address(0x0));
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
    function transfer(address _to, uint256 _value) public returns (bool success) {
        _transfer(msg.sender, _to, _value);
        return true;
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
        
        // Store original allowance for restoration if transfer fails
        uint256 originalAllowance = allowance[_from][msg.sender];
        
        // Reduce allowance first (vulnerable pattern)
        allowance[_from][msg.sender] -= _value;
        
        // External call to recipient before internal transfer - VULNERABILITY POINT
        // This allows recipient to call back into transferFrom with remaining allowance
        if (isContract(_to)) {
            (bool _success, ) = _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
            // Continue even if callback fails
        }
        
        // Perform the actual transfer after external call
        _transfer(_from, _to, _value);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }

    // Helper function for contract detection (Solidity <0.6.0)
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
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
        emit Approval(msg.sender, _spender, _value);
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
    function approveAndCall(address _spender, uint256 _value, bytes memory _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, address(this), _extraData);
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
