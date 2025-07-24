/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by implementing a two-stage burn queue system. The vulnerability requires multiple transactions to exploit:
 * 
 * **Stage 1 - Burn Queueing (Transaction 1):**
 * - First call queues the burn amount in `pendingBurns[msg.sender]`
 * - External call to `burnNotificationContract.notifyBurnQueued()` before any state changes
 * - This creates an attack vector where the external contract can re-enter
 * 
 * **Stage 2 - Burn Execution (Transaction 2+):**
 * - Second call executes the queued burn
 * - External call to `burnNotificationContract.notifyBurnExecuting()` BEFORE state updates
 * - State changes (balance/supply reduction) happen AFTER external call - violating CEI pattern
 * - This enables reentrancy attacks during burn execution
 * 
 * **Multi-Transaction Exploitation Path:**
 * 1. **Transaction 1**: Attacker calls `burn()` to queue burn amount
 * 2. **Transaction 2**: Attacker calls `burn()` again to execute queued burn
 * 3. **During Transaction 2**: The external `notifyBurnExecuting()` call allows reentrancy
 * 4. **Reentrancy Attack**: Malicious contract can re-enter `burn()` before state updates complete
 * 5. **State Inconsistency**: Multiple burns can be executed against the same queued amount
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability exploits the persistent state in `pendingBurns` mapping between transactions
 * - First transaction sets up the vulnerable state, second transaction triggers the exploitable external call
 * - Cannot be exploited in a single transaction due to the two-stage gating mechanism
 * - Requires accumulated state changes across multiple calls to create the attack window
 * 
 * **Attack Scenario:**
 * 1. Deploy malicious `IBurnNotifier` contract
 * 2. Transaction 1: Call `burn(1000)` → queues burn
 * 3. Transaction 2: Call `burn(1000)` → triggers execution
 * 4. During `notifyBurnExecuting()` callback: Re-enter `burn()` multiple times
 * 5. Result: Multiple burns executed against same queued amount, draining contract balance
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
    function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public;
}

interface IBurnNotifier {
    function notifyBurnQueued(address from, uint256 value, uint256 nonce) external;
    function notifyBurnExecuting(address from, uint256 value, uint256 nonce) external;
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
     * Constrctor function
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
        Frozen(target, froze);
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
        Transfer(_from, _to, _value);
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
// State variables for burn queue system (would need to be added to contract)
    mapping(address => uint256) public pendingBurns;
    mapping(address => uint256) public burnNonce;
    address public burnNotificationContract;
    
    function burn(uint256 _value) onlyOwner public returns (bool success)  {
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        
        // Stage 1: Queue the burn if not already queued
        if (pendingBurns[msg.sender] == 0) {
            pendingBurns[msg.sender] = _value;
            burnNonce[msg.sender]++;
            
            // External call for burn validation/notification - VULNERABLE TO REENTRANCY
            if (burnNotificationContract != address(0)) {
                IBurnNotifier(burnNotificationContract).notifyBurnQueued(msg.sender, _value, burnNonce[msg.sender]);
            }
            
            return true; // Burn queued but not executed
        }
        
        // Stage 2: Execute the queued burn
        uint256 queuedAmount = pendingBurns[msg.sender];
        require(queuedAmount > 0, "No burn queued");
        require(balanceOf[msg.sender] >= queuedAmount, "Insufficient balance for queued burn");
        
        // External call for burn execution notification - VULNERABLE TO REENTRANCY
        if (burnNotificationContract != address(0)) {
            IBurnNotifier(burnNotificationContract).notifyBurnExecuting(msg.sender, queuedAmount, burnNonce[msg.sender]);
        }
        
        // State changes AFTER external call - violates CEI pattern
        balanceOf[msg.sender] -= queuedAmount;
        totalSupply -= queuedAmount;
        pendingBurns[msg.sender] = 0;
        
        Burn(msg.sender, queuedAmount);
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
        Burn(_from, _value);
        return true;
    }
}