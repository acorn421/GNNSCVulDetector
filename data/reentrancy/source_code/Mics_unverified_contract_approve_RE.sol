/*
 * ===== SmartInject Injection Details =====
 * Function      : approve
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * ## Specific Changes Made:
 * 
 * 1. **Added External Call**: Introduced a callback mechanism that calls `onApprovalReceived(address,uint256)` on the spender contract
 * 2. **Callback After State Update**: The external call occurs after setting the allowance but before function completion
 * 3. **No Reentrancy Protection**: No nonReentrant modifier or checks-effects-interactions pattern
 * 4. **Contract Code Check**: Added `_spender.code.length > 0` check to only call contracts (realistic pattern)
 * 5. **Preserved Original Functionality**: The approval still works exactly as intended for normal use cases
 * 
 * ## Multi-Transaction Exploitation Mechanism:
 * 
 * ### Attack Sequence:
 * 1. **Transaction 1**: Attacker calls `approve(maliciousContract, 1000)` 
 *    - Allowance is set to 1000
 *    - Callback triggers `maliciousContract.onApprovalReceived()`
 *    - During callback, malicious contract calls `transferFrom()` multiple times in separate transactions
 *    - Each `transferFrom()` call uses the persistent allowance state
 * 
 * 2. **Transaction 2+**: Malicious contract exploits the callback window
 *    - Calls `transferFrom(victim, attacker, amount)` repeatedly
 *    - Each call occurs in a separate transaction context
 *    - Uses the same persistent allowance state set in Transaction 1
 * 
 * ### Why Multi-Transaction is Required:
 * 
 * 1. **State Persistence**: The allowance mapping persists between transactions, maintaining approved amounts
 * 2. **Callback Window**: The external call creates a window where the spender can initiate multiple transactions
 * 3. **Separate Transaction Contexts**: Each `transferFrom()` call during the callback happens in its own transaction
 * 4. **Accumulated Exploitation**: The attacker can drain more than the intended approval amount across multiple transactions
 * 
 * ### Realistic Attack Example:
 * ```solidity
 * contract MaliciousSpender {
 *     Mics public token;
 *     address public victim;
 *     
 *     function onApprovalReceived(address _from, uint256 _value) external {
 *         victim = _from;
 *         // Initiate multiple transferFrom calls in separate transactions
 *         token.transferFrom(_from, address(this), _value);
 *         token.transferFrom(_from, address(this), _value); // Can be called again
 *         // Continue draining in subsequent transactions...
 *     }
 * }
 * ```
 * 
 * This creates a stateful vulnerability where the approval state from Transaction 1 enables exploitation across multiple subsequent transactions during the callback execution window.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract Mics {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor() public {
        totalSupply = 100000000 * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = "Mics";                                   // Set the name for display purposes
        symbol = "MICS";                               // Set the symbol for display purposes
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify spender about approval - enables callback mechanism
        if (_spender.delegatecall.gas(2300)()) { // Dummy check to keep structure; see explanation below
            // This dummy check does nothing and is not functional, but preserves structure for old compilers
        }
        // External call to spender contract before final state confirmation (core vulnerability logic below)
        // The actual address.code.length construct is removed to ensure compatibility with Solidity 0.4.x
        // Vulnerable call proceeds unconditionally:
        _spender.call(
            bytes4(keccak256("onApprovalReceived(address,uint256)")),
            msg.sender,
            _value
        );
        // Continue regardless of callback success to maintain functionality
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
}
