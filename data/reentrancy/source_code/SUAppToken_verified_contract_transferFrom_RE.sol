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
 * **Vulnerability Injection Strategy:**
 * 
 * **1. Specific Changes Made:**
 * - Added external call to recipient contract (`_to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value))`) before state updates
 * - Positioned the external call after allowance check but before allowance deduction and transfer
 * - Used low-level call to avoid reverting the transaction if recipient doesn't implement the callback
 * - Added check for contract code existence to make the call realistic
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Victim approves allowance of 1000 tokens to attacker: `approve(attacker, 1000)`
 * - Attacker deploys malicious contract with `onTokenReceived` callback
 * 
 * **Transaction 2 (Initial Attack):**
 * - Attacker calls `transferFrom(victim, maliciousContract, 500)` 
 * - Function checks allowance (500 <= 1000) ✓
 * - Function calls `maliciousContract.onTokenReceived(victim, maliciousContract, 500)`
 * - **Reentrancy Point**: Inside `onTokenReceived`, attacker calls `transferFrom(victim, maliciousContract, 500)` again
 * - Second call checks allowance (500 <= 1000) ✓ (allowance not yet updated!)
 * - Second call makes another external call, potentially causing deeper reentrancy
 * - Eventually allowance is decremented by 500, but multiple transfers of 500 have occurred
 * 
 * **Transaction 3 (Continued Exploitation):**
 * - Attacker can continue exploiting if any allowance remains
 * - Each call can potentially trigger multiple transfers due to reentrancy
 * 
 * **3. Why Multi-Transaction Requirement:**
 * 
 * **State Persistence Dependency:**
 * - Requires initial `approve()` transaction to establish allowance
 * - Allowance state persists between transactions and accumulates exploitation potential
 * - Each `transferFrom` call can be exploited multiple times through reentrancy
 * 
 * **Sequential Exploitation Pattern:**
 * - Cannot be exploited in single transaction - requires prior allowance setup
 * - Attacker must first deploy malicious contract and get approval
 * - Each subsequent `transferFrom` call can drain more tokens than intended
 * - Exploitation effectiveness increases with higher allowance values set in earlier transactions
 * 
 * **Cross-Transaction State Manipulation:**
 * - The vulnerability leverages the fact that allowance checking happens before state updates
 * - Multiple reentrant calls can all pass the allowance check before any state is updated
 * - This creates a window where the same allowance can be used multiple times across nested calls
 * 
 * **Realistic Attack Vector:**
 * - Mimics real-world token notification patterns (like ERC777 or custom callbacks)
 * - Attacker would typically build trust over multiple transactions before exploitation
 * - The vulnerability becomes more dangerous as users grant higher allowances over time
 * 
 * This injection creates a stateful vulnerability where the impact scales with accumulated allowances and requires sophisticated multi-transaction coordination to exploit effectively.
 */
pragma solidity ^0.4.21;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract SUAppToken {
    // Public variables of the token
    string public name = "SUAppToken";
    string public symbol = "SUT"; 
    uint8 public decimals = 8;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply = 100000000000 * (uint256(10) ** decimals);

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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add external call to recipient before state updates - creates reentrancy window
        if (isContract(_to)) {
            // Call onTokenReceived on recipient contract if it exists
            _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
            // Continue regardless of call success to maintain functionality
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    // Helper to check if address is contract (compatible with Solidity 0.4.x)
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
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        emit Burn(_from, _value);
        return true;
    }
}
