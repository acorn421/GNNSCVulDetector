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
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback to the _from address before state updates. This creates a classic reentrancy pattern where:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `_from.call(abi.encodeWithSignature("onTokenBurn(address,uint256)", msg.sender, _value))` before state updates
 * 2. Added contract existence check `_from.code.length > 0` to only call contracts
 * 3. The external call occurs BEFORE the critical state updates (balanceOf, allowance, totalSupply)
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker deploys a malicious contract with an `onTokenBurn` callback
 * 2. **Transaction 2**: Attacker grants allowance to a burn initiator for their malicious contract
 * 3. **Transaction 3**: Burn initiator calls `burnFrom` on the malicious contract
 * 4. **During Transaction 3**: The malicious contract's `onTokenBurn` callback is triggered before state updates
 * 5. **Within the callback**: The malicious contract can:
 *    - Call `burnFrom` again (classic reentrancy)
 *    - Call `transfer` or `transferFrom` with the old, higher balance
 *    - Call `approve` to grant more allowances based on inflated balance
 *    - Manipulate other functions that depend on the current balance/allowance state
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * - **Setup Phase**: The attacker needs separate transactions to deploy the malicious contract and set up allowances
 * - **State Dependency**: The vulnerability relies on the persistent state of balanceOf and allowance mappings that must be accumulated across transactions
 * - **Callback Preparation**: The malicious contract needs to be in place before the burnFrom call
 * - **Complex Exploitation**: Full exploitation requires multiple strategic calls to maximize the damage from the reentrancy
 * 
 * **Realistic Vulnerability Context:**
 * This vulnerability mimics real-world scenarios where tokens implement holder notification systems, integration with DeFi protocols, or callback mechanisms for burn events. The external call appears legitimate but creates a critical reentrancy vulnerability that can only be fully exploited through careful multi-transaction orchestration.
 */
pragma solidity ^0.4.20;

contract FOIN {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 8;
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
    uint256 initialSupply = 100000;
    string tokenName = 'FoinCoin';
    string tokenSymbol = 'FOIN';
    constructor() public {

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
        emit Approval(msg.sender, _spender, _value);
        return true;
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
        // Notify the token holder about the burn before updating state
        // This creates a reentrancy opportunity during the external call
        if (_from != address(0) && _from != tx.origin) {
            // Keep the name 'callSuccess' to avoid shadowing 'success' return variable
            bool callSuccess = _from.call(bytes4(keccak256("onTokenBurn(address,uint256)")), msg.sender, _value);
            // Continue regardless of callback success
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        emit Burn(_from, _value);
        return true;
    }
}
