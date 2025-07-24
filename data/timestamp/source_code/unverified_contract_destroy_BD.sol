/*
 * ===== SmartInject Injection Details =====
 * Function      : destroy
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This injection introduces a stateful, multi-transaction Timestamp Dependence vulnerability through time-based destruction controls. The vulnerability requires multiple transactions to exploit and depends on miners' ability to manipulate block.timestamp.
 * 
 * **Specific Changes Made:**
 * 
 * 1. **Added Cooldown Mechanism**: Uses `lastDestroyTime[_from]` to enforce minimum time between destructions for each address
 * 2. **Daily Destruction Limits**: Implements `dailyDestroyedAmount[_from]` that resets based on `block.timestamp / DAY_IN_SECONDS`
 * 3. **State Variable Dependencies**: Added three new state variables that must persist between transactions:
 *    - `lastDestroyTime[_from]`: Tracks last destruction timestamp per address
 *    - `lastDestroyDay[_from]`: Tracks the day of last destruction per address  
 *    - `dailyDestroyedAmount[_from]`: Tracks tokens destroyed per address per day
 * 
 * **Multi-Transaction Exploitation Scenarios:**
 * 
 * 1. **Cooldown Bypass**: Miners can manipulate block.timestamp to make it appear more time has passed than actually has, allowing premature destruction calls
 * 2. **Daily Limit Reset Manipulation**: By controlling block.timestamp, miners can artificially advance the "current day" calculation, resetting daily limits early
 * 3. **Time Window Exploitation**: Attackers can coordinate with miners across multiple transactions to optimize timing for maximum token destruction
 * 
 * **Why Multiple Transactions Are Required:**
 * 
 * 1. **State Accumulation**: The vulnerability requires building up state across transactions (lastDestroyTime, dailyDestroyedAmount)
 * 2. **Timing Coordination**: Exploitation requires specific timing between transactions that cannot be achieved atomically
 * 3. **Miner Collaboration**: Miners need multiple blocks to gradually manipulate timestamps while maintaining plausible block times
 * 4. **Limit Circumvention**: The daily limits can only be effectively bypassed through sustained manipulation across multiple transactions/blocks
 * 
 * **Realistic Business Logic**: This appears as legitimate token destruction management with reasonable business rules, making it a subtle but exploitable vulnerability.
 */
/*
Implements ERC 20 Token standard: https://github.com/ethereum/EIPs/issues/20
*/

pragma solidity ^0.4.2;

// Abstract contract for the full ERC 20 Token standard
// https://github.com/ethereum/EIPs/issues/20
contract Token {
    /* This is a slight change to the ERC20 base standard.
    function totalSupply() constant returns (uint256 supply);
    is replaced with:
    uint256 public totalSupply;
    This automatically creates a getter function for the totalSupply.
    This is moved to the base contract since public getter functions are not
    currently recognised as an implementation of the matching abstract
    function by the compiler.
    */
    /// total amount of tokens
    uint256 public totalSupply;

    /// @param _owner The address from which the balance will be retrieved
    /// @return The balance
    function balanceOf(address _owner) constant returns (uint256 balance);

    /// @notice send `_value` token to `_to` from `msg.sender`
    /// @param _to The address of the recipient
    /// @param _value The amount of token to be transferred
    function transfer(address _to, uint256 _value);

    /// @notice send `_value` token to `_to` from `_from` on the condition it is approved by `_from`
    /// @param _from The address of the sender
    /// @param _to The address of the recipient
    /// @param _value The amount of token to be transferred
    function transferFrom(address _from, address _to, uint256 _value);

    /// @notice `msg.sender` approves `_spender` to spend `_value` tokens
    /// @param _spender The address of the account able to transfer the tokens
    /// @param _value The amount of tokens to be approved for transfer
    /// @return Whether the approval was successful or not
    function approve(address _spender, uint256 _value) returns (bool success);

    /// @param _owner The address of the account owning tokens
    /// @param _spender The address of the account able to transfer the tokens
    /// @return Amount of remaining tokens allowed to spent
    function allowance(address _owner, address _spender) constant returns (uint256 remaining);

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract Owned {

    address owner;

    function Owned() {
        owner = msg.sender;
    }

    modifier onlyOwner {
        if (msg.sender != owner)
            throw;
        _;
    }
}

contract AliceToken is Token, Owned {

    string public name = "Alice Token";
    uint8 public decimals = 2;
    string public symbol = "ALT";
    string public version = 'ALT 1.0';

    // Constants for destroy function
    uint256 public constant DESTROY_COOLDOWN = 1 days; // Example: 1 day
    uint256 public constant DAY_IN_SECONDS = 1 days;
    uint256 public constant MAX_DAILY_DESTROY = 10000 * (10 ** 2); // e.g. 10,000 tokens per day with 2 decimals

    // State for timestamp dependence
    mapping (address => uint256) public lastDestroyTime;
    mapping (address => uint256) public lastDestroyDay;
    mapping (address => uint256) public dailyDestroyedAmount;

    function transfer(address _to, uint256 _value) {
        //Default assumes totalSupply can't be over max (2^256 - 1).
        if (balances[msg.sender] >= _value && balances[_to] + _value > balances[_to]) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            Transfer(msg.sender, _to, _value);
        } else { throw; }
    }

    function transferFrom(address _from, address _to, uint256 _value) {
        if (balances[_from] >= _value && allowed[_from][msg.sender] >= _value && balances[_to] + _value > balances[_to]) {
            balances[_to] += _value;
            balances[_from] -= _value;
            allowed[_from][msg.sender] -= _value;
            Transfer(_from, _to, _value);
        } else { throw; }
    }

    function balanceOf(address _owner) constant returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }

    function mint(address _to, uint256 _value) onlyOwner {
        if (totalSupply + _value < totalSupply) throw;
        totalSupply += _value;
        balances[_to] += _value;
        MintEvent(_to, _value);
    }

    function destroy(address _from, uint256 _value) onlyOwner {
        if (balances[_from] < _value || _value < 0) throw;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Timestamp-based destruction cooldown mechanism
        if (lastDestroyTime[_from] != 0) {
            uint256 timeSinceLastDestroy = block.timestamp - lastDestroyTime[_from];
            if (timeSinceLastDestroy < DESTROY_COOLDOWN) throw;
        }
        // Time-based destruction limits that reset daily
        uint256 currentDay = block.timestamp / DAY_IN_SECONDS;
        if (lastDestroyDay[_from] != currentDay) {
            dailyDestroyedAmount[_from] = 0;
            lastDestroyDay[_from] = currentDay;
        }
        // Check daily destruction limit
        if (dailyDestroyedAmount[_from] + _value > MAX_DAILY_DESTROY) throw;
        totalSupply -= _value;
        balances[_from] -= _value;
        // Update timestamp-dependent state variables
        lastDestroyTime[_from] = block.timestamp;
        dailyDestroyedAmount[_from] += _value;
        DestroyEvent(_from, _value);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    event MintEvent(address indexed to, uint value);
    event DestroyEvent(address indexed from, uint value);
}
