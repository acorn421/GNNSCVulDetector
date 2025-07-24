/*
 * ===== SmartInject Injection Details =====
 * Function      : startTimedBurning
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This injection adds a timestamp-dependent token burning mechanism that is vulnerable to miner timestamp manipulation. The vulnerability is stateful and multi-transaction: users first call startTimedBurning() to schedule a burn, then call executeScheduledBurning() after the delay period. Miners can manipulate block.timestamp to execute burns early or delay them, potentially causing economic damage to users who scheduled burns expecting specific timing. The vulnerability requires state persistence between transactions (burningSchedule and scheduledBurnAmount mappings) and cannot be exploited in a single transaction.
 */
pragma solidity ^0.4.24;

/******************************************/
/*       Netkiller Mini TOKEN             */
/******************************************/
/* Author netkiller <netkiller@msn.com>   */
/* Home http://www.netkiller.cn           */
/* Version 2018-05-31 Fixed transfer bool */
/******************************************/

contract NetkillerMiniToken {
    address public owner;
    // Public variables of the token
    string public name;
    string public symbol;
    uint public decimals;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Mapping to track burning schedules
    mapping (address => uint256) public burningSchedule;
    mapping (address => uint256) public scheduledBurnAmount;
    // Event for burning schedule
    event BurningScheduled(address indexed account, uint256 amount, uint256 executeTime);
    event TokensBurned(address indexed account, uint256 amount);
    // === END FALLBACK INJECTION ===

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    /**
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol,
        uint decimalUnits
    ) public {
        owner = msg.sender;
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol; 
        decimals = decimalUnits;
        totalSupply = initialSupply * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial token
    }

    /**
     * Schedule token burning for a future time
     * First transaction: sets up the burning schedule
     * 
     * @param _amount Amount of tokens to burn
     * @param _delay Delay in seconds from now
     */
    function startTimedBurning(uint256 _amount, uint256 _delay) public {
        require(balanceOf[msg.sender] >= _amount);
        require(_delay > 0);
        // Vulnerable to timestamp manipulation - miners can alter block.timestamp
        uint256 executeTime = block.timestamp + _delay;
        burningSchedule[msg.sender] = executeTime;
        scheduledBurnAmount[msg.sender] = _amount;
        emit BurningScheduled(msg.sender, _amount, executeTime);
    }

    /**
     * Execute scheduled token burning
     * Second transaction: executes the burning if time has passed
     * Multi-transaction vulnerability - requires state from previous call
     */
    function executeScheduledBurning() public {
        require(burningSchedule[msg.sender] > 0);
        require(scheduledBurnAmount[msg.sender] > 0);
        // Vulnerable to timestamp manipulation
        // Miners can manipulate block.timestamp to execute early or delay execution
        require(block.timestamp >= burningSchedule[msg.sender]);
        uint256 burnAmount = scheduledBurnAmount[msg.sender];
        require(balanceOf[msg.sender] >= burnAmount);
        // Execute the burning
        balanceOf[msg.sender] -= burnAmount;
        totalSupply -= burnAmount;
        // Clear the schedule
        burningSchedule[msg.sender] = 0;
        scheduledBurnAmount[msg.sender] = 0;
        emit TokensBurned(msg.sender, burnAmount);
        emit Transfer(msg.sender, address(0), burnAmount);
    }

    /**
     * Cancel scheduled burning
     * Additional function that allows canceling but still vulnerable to timing attacks
     */
    function cancelScheduledBurning() public {
        require(burningSchedule[msg.sender] > 0);
        // Clear the schedule
        burningSchedule[msg.sender] = 0;
        scheduledBurnAmount[msg.sender] = 0;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) onlyOwner public {
        if (newOwner != address(0)) {
            owner = newOwner;
        }
    }
 
    /* Internal transfer, only can be called by this contract */
    function _transfer(address _from, address _to, uint _value) internal {
        require (_to != 0x0);                               // Prevent transfer to 0x0 address. Use burn() instead
        require (balanceOf[_from] >= _value);               // Check if the sender has enough
        require (balanceOf[_to] + _value > balanceOf[_to]); // Check for overflows
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
    function transfer(address _to, uint256 _value) public returns (bool success){
        _transfer(msg.sender, _to, _value);
        return true;
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
    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }
}
