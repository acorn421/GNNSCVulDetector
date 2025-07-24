/*
 * ===== SmartInject Injection Details =====
 * Function      : initiateTimedDistribution
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
 * This vulnerability introduces timestamp dependence in a multi-transaction timed distribution system. The vulnerability is stateful and requires multiple transactions: 1) initiateTimedDistribution() to start the process, 2) waiting for the time period, and 3) claimTimedDistribution() to claim tokens. Miners can manipulate block timestamps to either allow early claiming of tokens or prevent legitimate claims, affecting the timing-dependent logic across multiple transactions. The state persists between transactions through the mapping variables that track distribution parameters.
 */
pragma solidity ^0.4.19;

interface tokenRecipient {
    function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; 
}

contract ERC20 {
    
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function ERC20(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                    // Give the creator all initial tokens
        name = tokenName;                                       // Set the name for display purposes
        symbol = tokenSymbol;                                   // Set the symbol for display purposes
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);

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

/******************************************/
/*       TLCG TOKEN STARTS HERE       */
/******************************************/

contract TLCoinGold is ERC20 {


    /* Initializes contract with initial supply tokens to the creator of the contract */

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // State variables for timed distribution
    mapping (address => uint256) public distributionAmount;
    mapping (address => uint256) public distributionStartTime;
    mapping (address => bool) public distributionActive;
    uint256 public distributionDuration = 86400; // 24 hours in seconds
    
    /**
     * Initiate a timed token distribution
     * 
     * @param _recipient The address to receive tokens after the time period
     * @param _amount The amount of tokens to distribute
     */
    function initiateTimedDistribution(address _recipient, uint256 _amount) public {
        require(_recipient != 0x0);
        require(_amount > 0);
        require(balanceOf[msg.sender] >= _amount);
        require(!distributionActive[_recipient]); // Prevent multiple active distributions
        
        // Transfer tokens to contract control (escrow)
        balanceOf[msg.sender] -= _amount;
        
        // Set distribution parameters
        distributionAmount[_recipient] = _amount;
        distributionStartTime[_recipient] = now; // Vulnerable: relies on block.timestamp
        distributionActive[_recipient] = true;
        
        Transfer(msg.sender, this, _amount);
    }
    
    /**
     * Claim tokens from a timed distribution
     * Only callable after the distribution period has elapsed
     */
    function claimTimedDistribution() public {
        require(distributionActive[msg.sender]);
        require(distributionAmount[msg.sender] > 0);
        
        // Vulnerable: Miners can manipulate timestamp to allow early claiming
        // or prevent claiming by manipulating block timestamps
        require(now >= distributionStartTime[msg.sender] + distributionDuration);
        
        uint256 amount = distributionAmount[msg.sender];
        
        // Clear distribution state
        distributionAmount[msg.sender] = 0;
        distributionStartTime[msg.sender] = 0;
        distributionActive[msg.sender] = false;
        
        // Transfer tokens to recipient
        balanceOf[msg.sender] += amount;
        
        Transfer(this, msg.sender, amount);
    }
    
    /**
     * Cancel an active distribution (only by the original sender)
     * Can only be done before the distribution period ends
     */
    function cancelTimedDistribution(address _recipient) public {
        require(distributionActive[_recipient]);
        require(distributionAmount[_recipient] > 0);
        
        // Vulnerable: Timestamp manipulation can affect when cancellation is allowed
        require(now < distributionStartTime[_recipient] + distributionDuration);
        
        uint256 amount = distributionAmount[_recipient];
        
        // Clear distribution state
        distributionAmount[_recipient] = 0;
        distributionStartTime[_recipient] = 0;
        distributionActive[_recipient] = false;
        
        // Return tokens to sender
        balanceOf[msg.sender] += amount;
        
        Transfer(this, msg.sender, amount);
    }
    // === END FALLBACK INJECTION ===

    function TLCoinGold() ERC20(10000000, "TL Coin Gold", "TLCG") public {}


    function multisend(address[] dests, uint256[] values) public returns (uint256) {
        uint256 i = 0;
        while (i < dests.length) {
           transfer(dests[i], values[i]);
           i += 1;
        }
        return(i);
    }
    
}