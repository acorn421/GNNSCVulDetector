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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding external calls to the _from address at strategic points during state updates. The vulnerability creates windows where state is partially updated across multiple transactions:
 * 
 * 1. **External Call Integration**: Added two external calls to `onTokensBurned` and `onBurnComplete` callbacks on the _from address, creating natural reentrancy points.
 * 
 * 2. **State Fragmentation**: State updates are now fragmented across the external calls:
 *    - First call occurs after validation but before any state changes
 *    - Balance is updated after first external call
 *    - Allowance is updated between the two external calls
 *    - Total supply is updated after the second external call
 * 
 * 3. **Multi-Transaction Exploitation**: The vulnerability requires multiple transactions to exploit:
 *    - **Transaction 1**: Initial burnFrom call triggers first external call
 *    - **Transaction 2**: Reentrant call during onTokensBurned callback can manipulate allowances or trigger additional burns while balanceOf is not yet updated
 *    - **Transaction 3**: Additional exploitation during onBurnComplete callback when balanceOf and allowance are updated but totalSupply is not
 *    - **Transaction 4**: Final state exploitation after all updates complete
 * 
 * 4. **Attack Vector**: An attacker can:
 *    - Deploy a malicious contract as the token holder (_from)
 *    - Implement onTokensBurned and onBurnComplete callbacks
 *    - Use reentrancy to call burnFrom again during the callbacks
 *    - Exploit the inconsistent state where some variables are updated but others are not
 *    - Manipulate allowances or trigger additional burns during the state transition windows
 * 
 * 5. **Realistic Integration**: The callbacks represent legitimate token burn notification mechanisms that might be implemented in advanced ERC20 tokens, making the vulnerability subtle and realistic.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract MAGICCOINERC20 {
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

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    /**
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function MAGICCOINERC20(
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Introduce external call before all state updates are complete
        // This creates a reentrancy window where state is partially updated
        if (_from.call(bytes4(keccak256("onTokensBurned(address,uint256)")), msg.sender, _value)) {
            // External call succeeded, continue with partial state update
        }
        
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        
        // Create a multi-transaction vulnerability window
        // Allowance is updated after external call but before totalSupply
        // This creates inconsistent state across multiple transactions
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        
        // Additional external call that can be exploited across transactions
        // State is now partially updated, creating multi-transaction attack vector
        if (_from.call(bytes4(keccak256("onBurnComplete(address,uint256)")), msg.sender, _value)) {
            // Allow for potential reentrancy during state transition
        }
        
        totalSupply -= _value;                              // Update totalSupply (final state update)
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Burn(_from, _value);
        return true;
    }
}