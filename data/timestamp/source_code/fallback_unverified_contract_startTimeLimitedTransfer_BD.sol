/*
 * ===== SmartInject Injection Details =====
 * Function      : startTimeLimitedTransfer
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This injection adds a time-limited transfer system that creates a stateful, multi-transaction timestamp dependence vulnerability. The vulnerability requires: 1) First transaction to start a time-limited transfer with startTimeLimitedTransfer(), 2) Second transaction to either execute with executeTimeLimitedTransfer() or cancel with cancelExpiredTransfer(). The vulnerability lies in the reliance on block.timestamp (now) for deadline validation, which can be manipulated by miners within certain bounds. An attacker (especially a miner) can manipulate timestamps to either extend deadlines when executing transfers or trigger early cancellations, potentially causing financial loss or unexpected state changes. The state persists between transactions through the mapping variables that track pending transfers, deadlines, and reserved funds.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract CrowdstartCoin {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Time-limited transfer functionality - state variables needed
    mapping(address => uint256) public transferDeadlines;
    mapping(address => uint256) public pendingTransferAmounts;
    mapping(address => address) public pendingTransferRecipients;
    bool public timeLimitedTransfersEnabled = true;
    // === END FALLBACK INJECTION ===

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function CrowdstartCoin(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
    }

    // === FALLBACK INJECTION FUNCTIONS ===

    /**
     * Start a time-limited transfer that must be completed within a deadline
     * This creates a pending transfer that can be executed later
     *
     * @param _to The address of the recipient
     * @param _value the amount to transfer
     * @param _deadline timestamp when transfer expires
     */
    function startTimeLimitedTransfer(address _to, uint256 _value, uint256 _deadline) public returns (bool success) {
        require(timeLimitedTransfersEnabled);
        require(_to != 0x0);
        require(_value > 0);
        require(balanceOf[msg.sender] >= _value);
        require(_deadline > now); // Vulnerable: relies on block.timestamp
        
        // Store pending transfer details
        transferDeadlines[msg.sender] = _deadline;
        pendingTransferAmounts[msg.sender] = _value;
        pendingTransferRecipients[msg.sender] = _to;
        
        // Reserve the funds by reducing sender's available balance
        balanceOf[msg.sender] -= _value;
        
        return true;
    }

    /**
     * Execute a previously started time-limited transfer
     * Can only be called before the deadline expires
     */
    function executeTimeLimitedTransfer() public returns (bool success) {
        require(pendingTransferAmounts[msg.sender] > 0);
        require(pendingTransferRecipients[msg.sender] != 0x0);
        require(now <= transferDeadlines[msg.sender]); // Vulnerable: relies on block.timestamp
        
        address recipient = pendingTransferRecipients[msg.sender];
        uint256 amount = pendingTransferAmounts[msg.sender];
        
        // Check for overflow in recipient balance
        require(balanceOf[recipient] + amount > balanceOf[recipient]);
        
        // Complete the transfer
        balanceOf[recipient] += amount;
        
        // Clear pending transfer data
        delete transferDeadlines[msg.sender];
        delete pendingTransferAmounts[msg.sender];
        delete pendingTransferRecipients[msg.sender];
        
        Transfer(msg.sender, recipient, amount);
        return true;
    }

    /**
     * Cancel a pending time-limited transfer and restore funds
     * Can only be called after deadline has passed
     */
    function cancelExpiredTransfer() public returns (bool success) {
        require(pendingTransferAmounts[msg.sender] > 0);
        require(now > transferDeadlines[msg.sender]); // Vulnerable: relies on block.timestamp
        
        uint256 amount = pendingTransferAmounts[msg.sender];
        
        // Restore funds to sender
        balanceOf[msg.sender] += amount;
        
        // Clear pending transfer data
        delete transferDeadlines[msg.sender];
        delete pendingTransferAmounts[msg.sender];
        delete pendingTransferRecipients[msg.sender];
        
        return true;
    }
    // === END FALLBACK INJECTION FUNCTIONS ===

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        // Prevent transfer to 0x0 address.
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
        Transfer(_from, _to, _value);
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
