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
 * 1. Added external call to `tokenRecipient(_to).receiveApproval()` before state updates
 * 2. The external call is made after allowance check but before allowance decrement
 * 3. This creates a classic Checks-Effects-Interactions pattern violation
 * 4. The call only triggers if `_to` is a contract (code.length > 0)
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys malicious contract implementing `tokenRecipient` interface
 * - Attacker gets approval from victim for specific amount (e.g., 100 tokens)
 * - State: `allowance[victim][attacker] = 100`
 * 
 * **Transaction 2 (Initial Attack):**
 * - Attacker calls `transferFrom(victim, maliciousContract, 100)` 
 * - Function checks `allowance[victim][attacker] >= 100` ✓
 * - External call to `maliciousContract.receiveApproval()` is made
 * - **CRITICAL**: Allowance NOT YET decremented at this point
 * 
 * **Reentrancy from maliciousContract.receiveApproval():**
 * - Malicious contract immediately calls `transferFrom(victim, attacker, 100)` again
 * - Allowance check passes again: `allowance[victim][attacker]` still equals 100
 * - This triggers another external call, creating potential for multiple reentrant calls
 * - Each reentrant call can drain 100 tokens before any allowance is decremented
 * 
 * **State Persistence Across Transactions:**
 * - The allowance mapping persists between transactions
 * - Multiple reentrant calls can exploit the same allowance value
 * - Only after ALL reentrant calls complete does the original allowance get decremented
 * - Result: Attacker can drain multiple times the approved amount
 * 
 * **Why Multi-Transaction Dependency is Critical:**
 * 1. **Setup Required**: Attacker must first obtain approval in separate transaction
 * 2. **State Accumulation**: Each reentrant call builds on persistent allowance state
 * 3. **Cross-Call Exploitation**: Vulnerability exploits state that persists across multiple function calls
 * 4. **Not Single-Transaction Exploitable**: Cannot be exploited atomically without the external call triggering reentrancy
 * 
 * **Realistic Implementation Details:**
 * - Uses existing `tokenRecipient` interface already defined in contract
 * - Leverages legitimate recipient notification pattern common in ERC20 tokens
 * - Maintains all original functionality while introducing subtle vulnerability
 * - External call placement makes vulnerability non-obvious during code review
 */
pragma solidity ^0.4.13;

contract owned {
    address public owner;
    mapping (address =>  bool) public admins;

    constructor() public {
        owner = msg.sender;
        admins[msg.sender]=true;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    modifier onlyAdmin   {
        require(admins[msg.sender] == true);
        _;
    }

    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }

    function makeAdmin(address newAdmin, bool isAdmin) onlyOwner public {
        admins[newAdmin] = isAdmin;
    }
}

interface tokenRecipient {
    function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external;
}

contract EcoCrypto is owned {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    bool public usersCanUnfreeze;

    mapping (address => bool) public admin;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;

    mapping (address => mapping (address => uint256)) public allowance;
    mapping (address =>  bool) public frozen;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    // This generates a public event on the blockchain that will notify clients
    event Frozen(address indexed addr, bool frozen);

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor() public {
        uint256 initialSupply = 10000000000000000000;
        balanceOf[msg.sender] = initialSupply ;              // Give the creator all initial tokens
        totalSupply = initialSupply;                        // Update total supply
        name = "EcoCrypto Token";                                   // Set the name for display purposes
        symbol = "ECO";                               // Set the symbol for display purposes
        decimals = 8;                            // Amount of decimals for display purposes
        usersCanUnfreeze=false;
        admin[msg.sender]=true;
    }

    function setAdmin(address addr, bool enabled) onlyOwner public {
        admin[addr]=enabled;
    }


    function usersCanUnFreeze(bool can) onlyOwner public {
        usersCanUnfreeze=can;
    }

    /**
     * transferAndFreeze
     *
     * Function to transfer to and freeze and account at the same time
     */
    function transferAndFreeze (address target,  uint256 amount )  onlyAdmin public {
        _transfer(msg.sender, target, amount);
        freeze(target, true);
    }

    /**
     * _freeze internal
     *
     * function to freeze an account
     */
    function _freeze (address target, bool froze )  internal {
        frozen[target]=froze;
        emit Frozen(target, froze);
    }

    /**
     * freeze
     *
     * function to freeze an account
     */
    function freeze (address target, bool froze ) public   {
        if(froze || (!froze && !usersCanUnfreeze)) {
            require(admin[msg.sender]);
        }
        _freeze(target, froze);
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);                                   // Prevent transfer to 0x0 address. Use burn() instead
        require(!frozen[_from]);                       //prevent transfer from frozen address
        require(balanceOf[_from] >= _value);                // Check if the sender has enough
        require(balanceOf[_to] + _value > balanceOf[_to]); // Check for overflows
        balanceOf[_from] -= _value;                         // Subtract from the sender
        balanceOf[_to] += _value;                           // Add the same to the recipient
        emit Transfer(_from, _to, _value);
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
        require(!frozen[msg.sender]);                       //prevent transfer from frozen address
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
        require(!frozen[_from]);                       //prevent transfer from frozen address
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to notify recipient before state updates - VULNERABILITY INJECTION
        if (isContract(_to)) {
            tokenRecipient(_to).receiveApproval(_from, _value, this, "");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    // Internal function to check if address is a contract (for 0.4.x compat)
    function isContract(address _addr) internal view returns(bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
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
    function approveAndCall(address _spender, uint256 _value, bytes _extraData) onlyOwner public
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
    function burn(uint256 _value) onlyOwner public returns (bool success)  {
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        balanceOf[msg.sender] -= _value;            // Subtract from the sender
        totalSupply -= _value;                      // Updates totalSupply
        emit Burn(msg.sender, _value);
        return true;
    }

    /**
     * Destroy tokens from other ccount
     *
     * Remove `_value` tokens from the system irreversibly on behalf of `_from`.
     *
     * @param _from the address of the sender
     * @param _value the amount of money to burn
     */
    function burnFrom(address _from, uint256 _value) public  returns (bool success) {
        require(balanceOf[_from] >= _value);                // Check if the targeted balance is enough
        require(_value <= allowance[_from][msg.sender]);    // Check allowance
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        emit Burn(_from, _value);
        return true;
    }
}
