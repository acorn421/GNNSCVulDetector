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
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added Persistent State Storage**: Created `pendingCallbacks` mapping and `hasCallback` boolean state that persists between transactions to track callback information.
 * 
 * 2. **External Call Before State Update**: Added an external call to the recipient's `onTokenReceived` function BEFORE updating the allowance, violating the checks-effects-interactions pattern.
 * 
 * 3. **Delayed Callback Processing**: Implemented a `processCallback` function that can be called in separate transactions to process accumulated callback data, creating additional reentrancy opportunities.
 * 
 * 4. **Multi-Transaction Exploitation Pattern**: 
 *    - Transaction 1: Initial `transferFrom` call stores callback state and makes external call
 *    - Transaction 2: Malicious contract calls `processCallback` to trigger additional external calls
 *    - Transaction 3+: Multiple reentrancy attacks can be chained through the persistent state
 * 
 * 5. **State Persistence**: The `pendingCallbacks` and `hasCallback` mappings maintain state across transactions, enabling the vulnerability to be exploited over multiple calls rather than just within a single transaction.
 * 
 * **How it's exploited across multiple transactions:**
 * - Transaction 1: Attacker calls `transferFrom`, callback state is stored, external call is made
 * - Transaction 2: Attacker's contract receives the callback and can re-enter `transferFrom` with the allowance not yet decremented
 * - Transaction 3: `processCallback` is called, triggering another external call that can re-enter again
 * - The persistent state allows the attacker to exploit the same allowance multiple times across different transactions
 * 
 * **Why it requires multiple transactions:**
 * - The vulnerability relies on the persistent `pendingCallbacks` state that accumulates across transactions
 * - Each transaction can trigger external calls that set up state for exploitation in subsequent transactions
 * - The allowance is only decremented after the external call, but the callback state persists, allowing repeated exploitation
 * - A single transaction cannot fully exploit this because the callback processing and state accumulation requires separate transaction contexts
 */
pragma solidity ^0.4.16;
interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }
contract Mmcchain {
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
// Storage for delayed callbacks
    mapping(address => mapping(address => uint256)) public pendingCallbacks;
    mapping(address => bool) public hasCallback;
    
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        
        // Store callback information in state before external call
        pendingCallbacks[_from][_to] = _value;
        hasCallback[_to] = true;
        
        // External call to recipient (potential reentrancy point)
        if (isContract(_to)) {
            // Call recipient's callback function if it exists
            _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
            // Continue execution regardless of callback success
        }
        
        // State update AFTER external call - vulnerable to reentrancy
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Function to process accumulated callbacks in separate transactions
    function processCallback(address _from, address _to) public {
        require(hasCallback[_to]);
        uint256 callbackValue = pendingCallbacks[_from][_to];
        
        // Clear callback state
        delete pendingCallbacks[_from][_to];
        hasCallback[_to] = false;
        
        // Another external call that can be exploited
        if (isContract(_to)) {
            _to.call(abi.encodeWithSignature("onCallbackProcessed(address,address,uint256)", _from, _to, callbackValue));
        }
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        emit Burn(_from, _value);
        return true;
    }

    // Helper function to check if address is a contract. Compatible with Solidity 0.4.x
    function isContract(address _addr) internal view returns (bool) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}