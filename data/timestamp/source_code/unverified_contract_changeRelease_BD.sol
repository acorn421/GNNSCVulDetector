/*
 * ===== SmartInject Injection Details =====
 * Function      : changeRelease
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
 * Introduced a stateful timestamp dependence vulnerability that requires multiple transactions to exploit. The vulnerability uses accumulated "flexibility" based on time passed between function calls, allowing the owner to bypass the MIN_RELEASE_DATE restriction after accumulating enough flexibility through multiple transactions over time. This creates a multi-transaction attack vector where an owner can manipulate the release date in ways that should be restricted by calling the function multiple times across different blocks/timestamps.
 * 
 * **Specific Changes Made:**
 * 1. **Added State Variables** (would need to be added to contract): `lastReleaseChangeTime` and `accumulatedFlexibility` to track timestamp-based accumulation
 * 2. **Time-Based Accumulation Logic**: Added logic that accumulates "flexibility" points based on time elapsed between function calls
 * 3. **Bypass Mechanism**: Created a pathway to bypass the MIN_RELEASE_DATE restriction when sufficient flexibility is accumulated
 * 4. **Multi-Transaction Dependency**: The vulnerability requires multiple calls over time to build up flexibility before exploitation
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Setup Phase**: Owner calls `changeRelease()` multiple times over several days/weeks to accumulate flexibility
 * 2. **Exploitation Phase**: After accumulating 7+ days of flexibility, owner can bypass MIN_RELEASE_DATE restriction
 * 3. **Impact**: Owner can set release date to current timestamp, immediately enabling transfers
 * 
 * **Why Multiple Transactions Are Required:**
 * - Flexibility accumulates based on time elapsed between calls, requiring multiple transactions separated by time
 * - The bypass only becomes available after sufficient flexibility is accumulated through repeated calls
 * - Single-transaction exploitation is impossible because the flexibility must be built up over time through the timestamp-dependent accumulation mechanism
 */
pragma solidity ^0.4.24;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract Ownable {

    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
    
}

contract AzbitToken is Ownable {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;
    uint256 public releaseDate = 1546300800; //Tuesday, 01-Jan-19 00:00:00 UTC in RFC 2822
    uint256 public constant MIN_RELEASE_DATE = 1546300800; //Tuesday, 01-Jan-19 00:00:00 UTC in RFC 2822
    uint256 public constant MAX_RELEASE_DATE = 1559260800; //Friday, 31-May-19 00:00:00 UTC in RFC 2822

    // ======== Added missing variables for timestamp dependence vulnerability ========
    uint256 public lastReleaseChangeTime = 0;
    uint256 public accumulatedFlexibility = 0;
    // ===============================================================================

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    mapping (address => bool) public whiteList;

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
    function _transfer(address _from, address _to, uint _value) internal canTransfer {
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
    
    function addToWhiteList(address _address) public onlyOwner {
        whiteList[_address] = true;
    }
    
    function removeFromWhiteList(address _address) public onlyOwner {
        require(_address != owner);
        delete whiteList[_address];
    }
    
    function changeRelease(uint256 _date) public onlyOwner {
        require(_date > now && releaseDate > now && _date > MIN_RELEASE_DATE && _date < MAX_RELEASE_DATE);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Track timestamp-based "flexibility" that accumulates over multiple calls
        uint256 timeSinceLastChange = now - lastReleaseChangeTime;
        if (timeSinceLastChange > 0) {
            // Accumulate flexibility based on time passed - this creates exploitable state
            accumulatedFlexibility += timeSinceLastChange / 86400; // Add 1 flexibility per day
            if (accumulatedFlexibility > 30) {
                accumulatedFlexibility = 30; // Cap at 30 days of flexibility
            }
        }
        
        // Allow bypassing MIN_RELEASE_DATE restriction if enough flexibility accumulated
        if (accumulatedFlexibility >= 7) {
            // With 7+ days of accumulated flexibility, allow setting release date to current block timestamp
            // This creates a multi-transaction vulnerability where owner can bypass time restrictions
            if (_date >= now && _date < MAX_RELEASE_DATE) {
                releaseDate = _date;
                accumulatedFlexibility -= 7; // Consume 7 days of flexibility
                lastReleaseChangeTime = now;
                return;
            }
        }
        
        // Original logic with additional timestamp-based validation
        releaseDate = _date;
        lastReleaseChangeTime = now;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }
    
    modifier canTransfer() {
        require(now >= releaseDate || whiteList[msg.sender]);
        _;
    }
}
