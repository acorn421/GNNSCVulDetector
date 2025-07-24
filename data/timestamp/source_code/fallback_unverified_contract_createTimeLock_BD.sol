/*
 * ===== SmartInject Injection Details =====
 * Function      : createTimeLock
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
 * This vulnerability introduces a stateful, multi-transaction timestamp dependence flaw. The attack requires: 1) First transaction to create a time lock with createTimeLock(), 2) State persists with locked tokens and timestamp, 3) Second transaction to claim rewards early by exploiting miner's ability to manipulate block timestamp. The vulnerability is stateful because it depends on the locked rewards and timestamp state that persists between transactions. A malicious miner can manipulate block timestamps to unlock rewards earlier than intended by setting timestamps closer to the unlock time.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract touristoken {
    string public name;
    string public symbol;
    uint8 public decimals = 0;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Burn(address indexed from, uint256 value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // State variables for time-locked rewards
    mapping (address => uint256) public lockedRewards;
    mapping (address => uint256) public lockTimestamp;
    uint256 public constant LOCK_DURATION = 7 days;
    // === END FALLBACK INJECTION ===

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function TokenERC20(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = 7000000000;
        balanceOf[msg.sender] = totalSupply;
        name = "touristoken";
        symbol = "TOU";
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    /**
     * Create time-locked reward for user
     *
     * @param _user The address to create lock for
     * @param _amount The amount of tokens to lock
     */
    function createTimeLock(address _user, uint256 _amount) public {
        require(balanceOf[msg.sender] >= _amount);
        require(_user != 0x0);
        // Transfer tokens to contract for locking
        balanceOf[msg.sender] -= _amount;
        lockedRewards[_user] += _amount;
        // Set lock timestamp - vulnerable to miner manipulation
        lockTimestamp[_user] = now + LOCK_DURATION;
        Transfer(msg.sender, this, _amount);
    }
    /**
     * Claim unlocked rewards
     *
     * Users can claim their rewards after lock period expires
     */
    function claimRewards() public {
        require(lockedRewards[msg.sender] > 0);
        // Vulnerable: Uses block.timestamp which can be manipulated
        require(now >= lockTimestamp[msg.sender]);
        uint256 reward = lockedRewards[msg.sender];
        lockedRewards[msg.sender] = 0;
        lockTimestamp[msg.sender] = 0;
        // Give back locked tokens
        balanceOf[msg.sender] += reward;
        Transfer(this, msg.sender, reward);
    }
    /**
     * Emergency unlock - only available after extended period
     */
    function emergencyUnlock() public {
        require(lockedRewards[msg.sender] > 0);
        // Vulnerable: Extended period calculation using manipulable timestamp
        require(now >= lockTimestamp[msg.sender] + 30 days);
        uint256 reward = lockedRewards[msg.sender];
        lockedRewards[msg.sender] = 0;
        lockTimestamp[msg.sender] = 0;
        balanceOf[msg.sender] += reward;
        Transfer(this, msg.sender, reward);
    }
    // === END FALLBACK INJECTION ===

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
       Transfer(_from, _to, _value);
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
        require(_value <= allowance[_from][msg.sender]);    
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
        require(balanceOf[msg.sender] >= _value);   
        balanceOf[msg.sender] -= _value;            
        totalSupply -= _value;                      
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
        require(balanceOf[_from] >= _value);                
        require(_value <= allowance[_from][msg.sender]);    
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;             
        totalSupply -= _value;                              
        Burn(_from, _value);
        return true;
    }
}
