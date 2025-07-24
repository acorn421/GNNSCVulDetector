/*
 * ===== SmartInject Injection Details =====
 * Function      : startTimedTransferWindow
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
 * This introduces a timestamp dependence vulnerability that is stateful and requires multiple transactions. The vulnerability occurs because miners can manipulate block timestamps within certain bounds. An attacker who is also a miner could: 1) Call startTimedTransferWindow() to initiate a timed transfer, 2) Wait for the intended time window, 3) As a miner, manipulate the block timestamp when calling executeTimedTransfer() to either execute the transfer earlier than intended or prevent others from canceling their transfers by making it appear the window has already passed. This requires multiple transactions (start + execute) and maintains state between calls through the mapping variables.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

/**
 * v0.4.21+commit.dfe3193c
 */
contract CKT {
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // State variables for timed transfer functionality (moved to contract scope)
    mapping (address => uint256) public timedTransferWindowStart;
    mapping (address => uint256) public timedTransferAmount;
    mapping (address => address) public timedTransferRecipient;
    uint256 public constant TRANSFER_WINDOW_DURATION = 24 hours;
    // === END FALLBACK INJECTION DECLARATIONS ===

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function CKT() public {
        totalSupply = 200000000 * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = "Cryptokids Token";  // Set the name for display purposes
        symbol = "CKT";                               // Set the symbol for display purposes
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    /**
     * Start a timed transfer window
     * Allows user to prepare a transfer that can be executed after a time window
     *
     * @param _to The address to transfer to
     * @param _value The amount to transfer
     */
    function startTimedTransferWindow(address _to, uint256 _value) public {
        require(_to != 0x0);
        require(balanceOf[msg.sender] >= _value);
        require(timedTransferWindowStart[msg.sender] == 0); // No active window

        timedTransferWindowStart[msg.sender] = now;
        timedTransferAmount[msg.sender] = _value;
        timedTransferRecipient[msg.sender] = _to;
    }

    /**
     * Execute a timed transfer after the window period
     * Can only be called after the time window has passed
     */
    function executeTimedTransfer() public {
        require(timedTransferWindowStart[msg.sender] != 0); // Active window exists
        require(now >= timedTransferWindowStart[msg.sender] + TRANSFER_WINDOW_DURATION); // Window has passed

        uint256 amount = timedTransferAmount[msg.sender];
        address recipient = timedTransferRecipient[msg.sender];

        // Clear the timed transfer state
        timedTransferWindowStart[msg.sender] = 0;
        timedTransferAmount[msg.sender] = 0;
        timedTransferRecipient[msg.sender] = 0x0;

        _transfer(msg.sender, recipient, amount);
    }

    /**
     * Cancel a timed transfer window
     * Can only be called before the window expires
     */
    function cancelTimedTransfer() public {
        require(timedTransferWindowStart[msg.sender] != 0); // Active window exists
        require(now < timedTransferWindowStart[msg.sender] + TRANSFER_WINDOW_DURATION); // Window hasn't passed yet

        // Clear the timed transfer state
        timedTransferWindowStart[msg.sender] = 0;
        timedTransferAmount[msg.sender] = 0;
        timedTransferRecipient[msg.sender] = 0x0;
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
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        require((_value == 0) || (allowance[msg.sender][_spender] == 0));
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
}
