/*
 * ===== SmartInject Injection Details =====
 * Function      : freezeAccount
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the target contract before updating the frozen state. This allows the target to re-enter the contract and perform token transfers before the freeze is committed to storage.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call `target.call(abi.encodeWithSignature("onAccountFreeze(uint256)", till))` before the state update
 * 2. The call attempts to notify the target contract about the pending freeze
 * 3. State modification (`frozenAccount[target] = fi`) occurs AFTER the external call, creating a reentrancy window
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * Transaction 1 (Reentrancy Setup):
 * - Owner calls `freezeAccount(maliciousContract, timestamp)`
 * - The external call triggers `maliciousContract.onAccountFreeze()`
 * - Inside the callback, maliciousContract calls `transfer()` functions
 * - Since `frozenAccount[target].frozen` is still false, transfers succeed
 * - The malicious contract can drain its balance or perform other operations
 * - After callback returns, the account is finally marked as frozen
 * 
 * Transaction 2+ (Post-Exploitation):
 * - Any subsequent calls to transfer functions will now properly check the frozen state
 * - The account appears frozen in storage, but the damage was done during the reentrancy window
 * 
 * **Why Multiple Transactions Are Required:**
 * 1. The vulnerability requires the malicious contract to have a balance or allowances set up beforehand (previous transactions)
 * 2. The reentrancy window only exists during the execution of the `freezeAccount` function
 * 3. The malicious contract needs to be designed with the `onAccountFreeze` callback function (deployed in previous transaction)
 * 4. The exploitation involves the interaction between the freeze mechanism and the transfer functions, which rely on the persistent `frozenAccount` state
 * 
 * This creates a realistic time-of-check-time-of-use (TOCTOU) vulnerability where the frozen state is checked but not yet committed when the external call is made.
 */
pragma solidity ^0.4.18;

contract owned {
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
}

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract BalToken is owned {
    string public name;                 // Name of the Token
    string public symbol;               // Symbol of the Token
    uint8 public decimals = 18;         // Decimal Places for the token
    uint256 public totalSupply;         // Total Supply of the token

    struct frozenInfo {
        bool frozen;                    // Frozen state of the account
        uint till;                      // The timestamp account will be frozen till
    }
    
    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;

    // This creates an array with all allowances
    mapping (address => mapping (address => uint256)) public allowance;

    // This creates and array with all Frozen accounts with time limit
    mapping (address => frozenInfo) public frozenAccount;
    
    // This generates a public event on the blockchain that will notify clients
    event FrozenFunds(address target, bool frozen, uint till);

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public 
    {
        totalSupply = initialSupply * 10 ** uint256(decimals);      // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                        // Give the creator all initial tokens
        name = tokenName;                                           // Set the name for display purposes
        symbol = tokenSymbol;                                       // Set the symbol for display purposes
    }

    /**
     * Function for other contracts to call to get balances of individual accounts
     */
    function getBalanceOf(address _owner) public constant returns (uint256 balance) {
        return balanceOf[_owner];
    }    

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        require (_to != 0x0);                                           // Prevent transfer to 0x0 address.
        require (_to != address(this));                                 // Prevent transfer back to this contract
        require (balanceOf[_from] >= _value);                           // Check if the sender has enough
        require (balanceOf[_to] + _value > balanceOf[_to]);             // Check for overflows
        require(!(frozenAccount[_from].frozen));                        // Check if sender is frozen
        require(!(frozenAccount[_to].frozen));                          // Check if recipient is frozen
        uint previousBalances = balanceOf[_from] + balanceOf[_to];      // Save this value for assertion

        balanceOf[_from] -= _value;                                     // Subtract from the sender
        balanceOf[_to] += _value;                                       // Add the same to the recipient
        emit Transfer(_from, _to, _value);                                   // Transfer the token from _from to _to for the amount of _value
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);  // Asserts that the previous value matches the current value 
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
        allowance[_from][msg.sender] -= _value; // Subtract from the 
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
    function approve(address _spender, uint256 _value) public returns (bool success) {
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
    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    /// @notice `freeze? Prevent` `target` from sending & receiving tokens
    /// @param target Address to be frozen
    /// @param till Timestamp frozen till
    function freezeAccount(address target, uint till) onlyOwner public {
        require(!frozenAccount[target].frozen); 

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Vulnerable external call before state update - notify target if it's a contract
        if (isContract(target)) {
            target.call(abi.encodeWithSignature("onAccountFreeze(uint256)", till));
        }
        
        // State update occurs after external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        frozenInfo memory fi = frozenInfo(true, till);
        frozenAccount[target] = fi;
        emit FrozenFunds(target, true, till);

    }

    /// @notice `unfreeze? Allows` `target` from sending & receiving tokens
    /// @param target Address to be unfrozen
    function unfreezeAccount(address target) onlyOwner public {
        require(frozenAccount[target].frozen);
        require(frozenAccount[target].till < now);
        
        frozenInfo memory fi = frozenInfo(false, 0);
        frozenAccount[target] = fi;
        emit FrozenFunds(target, false, 0);
    }

    // Helper function to check if address is a contract
    function isContract(address _addr) internal view returns (bool) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}
