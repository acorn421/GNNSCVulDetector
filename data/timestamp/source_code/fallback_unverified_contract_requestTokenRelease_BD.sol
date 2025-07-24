/*
 * ===== SmartInject Injection Details =====
 * Function      : requestTokenRelease
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
 * This vulnerability introduces a timestamp dependence issue where miners can manipulate block timestamps to exploit the token release system. The vulnerability requires multiple transactions: first calling requestTokenRelease() to create a request, then calling processTokenRelease() to claim tokens. The state persists between transactions through the releaseRequests mapping. Miners can manipulate the 'now' timestamp to either accelerate normal releases or trigger emergency releases that give double tokens, making this a stateful multi-transaction vulnerability.
 */
pragma solidity ^0.4.20;

interface tokenRecipient { 
    function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; 
}

/**
 * Base Contract of ERC20
 */
 contract TokenOfResource {
	// Public variables of the token
    string public name;
    string public symbol;

    uint8 public decimals = 18;
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Token release request system with timestamp-based unlocking
    struct ReleaseRequest {
        uint256 amount;
        uint256 requestTime;
        bool processed;
    }
    
    mapping(address => ReleaseRequest) public releaseRequests;
    uint256 public releaseDelay = 1 hours; // Minimum delay for token release
    uint256 public emergencyReleaseTime = 24 hours; // Emergency release window
    
    event TokenReleaseRequested(address indexed requester, uint256 amount, uint256 requestTime);
    event TokenReleaseProcessed(address indexed requester, uint256 amount);

    /**
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor() public {
        totalSupply = 10000000000 * 10 ** uint256(decimals);   	// Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                    // Give the creator all initial tokens

        name = 'Resource Token';                                // Set the name for display purposes
        symbol = 'RT';                                         // Set the symbol for display purposes
    }

    /**
     * Request token release with time lock
     * 
     * @param _amount Amount of tokens to request for release
     */
    function requestTokenRelease(uint256 _amount) public returns (bool success) {
        require(_amount > 0, "Amount must be greater than zero");
        require(balanceOf[msg.sender] >= _amount, "Insufficient balance");
        require(releaseRequests[msg.sender].processed == true || releaseRequests[msg.sender].amount == 0, "Previous request pending");
        
        releaseRequests[msg.sender] = ReleaseRequest({
            amount: _amount,
            requestTime: now, // Vulnerable to timestamp manipulation
            processed: false
        });
        
        emit TokenReleaseRequested(msg.sender, _amount, now);
        return true;
    }
    
    /**
     * Process token release if time requirements are met
     */
    function processTokenRelease() public returns (bool success) {
        ReleaseRequest storage request = releaseRequests[msg.sender];
        require(request.amount > 0, "No release request found");
        require(request.processed == false, "Request already processed");
        
        // Vulnerable timestamp dependence - miners can manipulate
        if (now >= request.requestTime + releaseDelay) {
            // Normal release path
            balanceOf[msg.sender] += request.amount;
            totalSupply += request.amount;
            request.processed = true;
            
            emit TokenReleaseProcessed(msg.sender, request.amount);
            return true;
        } else if (now >= request.requestTime + emergencyReleaseTime) {
            // Emergency release path - also vulnerable to timestamp manipulation
            uint256 emergencyAmount = request.amount * 2; // Double tokens in emergency
            balanceOf[msg.sender] += emergencyAmount;
            totalSupply += emergencyAmount;
            request.processed = true;
            
            emit TokenReleaseProcessed(msg.sender, emergencyAmount);
            return true;
        }
        
        revert("Release time not reached");
    }
    // === END FALLBACK INJECTION ===

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
    function approve(address _spender, uint256 _value) public returns (bool success) {
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
    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
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

 }