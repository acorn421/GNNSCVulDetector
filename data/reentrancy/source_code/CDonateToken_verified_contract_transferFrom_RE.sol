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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * **Specific Changes Made:**
 * 1. **External Call Injection**: Added external call to recipient contract via `tokenRecipient(_to).receiveApproval()` before allowance state update
 * 2. **Violation of Checks-Effects-Interactions**: External call now occurs after allowance check but before allowance deduction
 * 3. **Contract Detection**: Added `_to.code.length > 0` check to ensure recipient is a contract (realistic enhancement)
 * 4. **Callback Mechanism**: Uses existing `tokenRecipient` interface to create legitimate-looking callback functionality
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Setup:**
 * - Token owner approves attacker contract X for 100 tokens via `approve(attackerContract, 100)`
 * - Attacker contract X is now authorized to spend 100 tokens on behalf of owner
 * - State: `allowance[owner][attackerContract] = 100`
 * 
 * **Transaction 2 - Initial Exploit:**
 * - Attacker calls `transferFrom(owner, attackerContract, 100)`
 * - Function checks `100 <= allowance[owner][attackerContract]` ✓ (passes)
 * - External call to `attackerContract.receiveApproval()` is made **before** allowance update
 * - During callback, attacker can re-enter `transferFrom()` with same parameters
 * - Original allowance still shows 100 (not yet decremented)
 * 
 * **Transaction 3+ - Continued Exploitation:**
 * - In the `receiveApproval` callback, attacker calls `transferFrom(owner, attackerContract, 100)` again
 * - Allowance check still passes because previous call hasn't finished updating state
 * - This creates a recursive chain allowing multiple transfers before any allowance updates
 * - Attacker can drain more tokens than originally approved
 * 
 * **Why Multi-Transaction Dependency is Critical:**
 * 
 * 1. **State Accumulation**: Requires pre-existing approval state from previous transaction
 * 2. **Persistent Allowance**: Vulnerability depends on allowance state that persists between transactions
 * 3. **Recursive Exploitation**: Each re-entrant call depends on state not yet updated from previous calls
 * 4. **Cross-Transaction State**: Original approval transaction creates exploitable state for subsequent attack transactions
 * 
 * **Realistic Vulnerability Characteristics:**
 * - Appears as legitimate enhancement for contract-to-contract transfers
 * - Uses existing `tokenRecipient` interface from contract context
 * - Maintains all original functionality and signatures
 * - Common pattern in token contracts for notification purposes
 * - Subtle violation of checks-effects-interactions pattern
 */
pragma solidity ^0.4.16;

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

contract TokenERC20 {
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
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

        // Enhanced functionality: notify recipient before updating allowance
        uint length;
        assembly {
            length := extcodesize(_to)
        }
        if (length > 0) {
            tokenRecipient(_to).receiveApproval(_from, _value, this, "");
        }

        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
}


contract CDonateToken is owned, TokenERC20 {

    /* Initializes contract with initial supply tokens to the creator of the contract */
    constructor(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) TokenERC20(initialSupply, tokenName, tokenSymbol) public {}
}
