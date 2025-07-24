/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
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
 * **Specific Changes Made:**
 * 1. Added an external call to `TokenBurnNotification(_from).onTokenBurn(msg.sender, _value)` after the initial checks but before state updates
 * 2. Added a condition to only call the notification if `_from` is a contract (has code) and is not the same as `msg.sender`
 * 3. The external call creates a reentrancy window between allowance validation and state updates
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Setup Phase:**
 * - Attacker sets up a malicious contract at address `_from` that implements `onTokenBurn`
 * - Attacker approves themselves for a large allowance (e.g., 1000 tokens)
 * - Attacker has sufficient balance (e.g., 1000 tokens)
 * 
 * **Transaction 2 - Exploitation Phase:**
 * - Attacker calls `burnFrom(maliciousContract, 500)` 
 * - Function validates: balance >= 500 ✓, allowance >= 500 ✓
 * - External call to `maliciousContract.onTokenBurn()` is made
 * - Inside the callback, malicious contract calls `burnFrom(maliciousContract, 500)` again
 * - Second call validates: balance still >= 500 ✓ (not updated yet), allowance still >= 500 ✓ (not updated yet)
 * - Second call completes, burning 500 tokens and updating state
 * - First call resumes and burns another 500 tokens
 * - **Result**: 1000 tokens burned but attacker only had allowance for 500
 * 
 * **Why Multi-Transaction Required:**
 * 1. **State Dependency**: The vulnerability relies on the persistent state of `allowance` and `balanceOf` mappings that exist between transactions
 * 2. **Setup Requirement**: The attacker must first establish allowance and deploy a malicious contract in separate transactions
 * 3. **Reentrancy Window**: The external call creates a state inconsistency window that can only be exploited through callback mechanisms requiring contract interaction
 * 4. **Accumulated State Exploitation**: The vulnerability exploits the fact that state checks pass based on values from previous transactions, but state updates haven't been applied yet
 * 
 * The vulnerability is stateful because it depends on persistent contract state (allowances, balances) and requires multiple transactions to set up the conditions and execute the exploit.
 */
/**
 *Submitted for verification at Etherscan.io on 2019-09-25
*/

pragma solidity ^0.4.19;
interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }
// Added the TokenBurnNotification interface to fix compilation error
interface TokenBurnNotification { function onTokenBurn(address _operator, uint256 _value) external; }
contract ESVtoken{
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
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    // Updated to a constructor for Solidity >=0.4.22 compatibility
    constructor (
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
     * Send `_value` tokens to `_to` in behalf of `_from`
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
     * Allows `_spender` to spend no more than `_value` tokens in your behalf
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
     * Allows `_spender` to spend no more than `_value` tokens in your behalf, and then ping the contract about it
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
        if(_from != msg.sender && extcodesize(_from) > 0) {
            TokenBurnNotification(_from).onTokenBurn(msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        emit Burn(_from, _value);
        return true;
    }
    
    // Helper to check contract code length (since .code not available in <0.8.x)
    function extcodesize(address _addr) internal view returns(uint size) {
        assembly { size := extcodesize(_addr) }
    }
}
