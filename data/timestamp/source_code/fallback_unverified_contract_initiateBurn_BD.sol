/*
 * ===== SmartInject Injection Details =====
 * Function      : initiateBurn
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence in a multi-transaction burn mechanism. The vulnerability requires: 1) First transaction to initiateBurn() which records current timestamp, 2) Waiting period where state persists, 3) Second transaction to executeBurn() which checks timestamp. Miners can manipulate timestamps within bounds to potentially bypass the intended cooldown period or delay execution. The vulnerability is stateful as it relies on persistent storage of burnRequestTime and burnRequests mappings across multiple transactions.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract HRChainERC20 {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 8;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Burn scheduling state
    mapping (address => uint256) public burnRequests;
    mapping (address => uint256) public burnRequestTime;
    uint256 public burnCooldownPeriod = 24 hours;
    // === END FALLBACK INJECTION ===

    /**
     * Constructor function
     */
    function HRChainERC20() public {
        totalSupply =12000000000000000;  // Update total supply with the decimal amount
        balanceOf[msg.sender] = 12000000000000000;                // Give the creator all initial tokens
        name = "Health Regimen Chain";                                   // Set the name for display purposes
        symbol = "HRC";                               // Set the symbol for display purposes
    }

    /**
     * Initiate a burn request with time delay for security
     */
    function initiateBurn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(_value > 0);

        burnRequests[msg.sender] = _value;
        burnRequestTime[msg.sender] = now; // Vulnerable timestamp dependency

        return true;
    }

    /**
     * Execute the burn after cooldown period
     */
    function executeBurn() public returns (bool success) {
        require(burnRequests[msg.sender] > 0);
        require(now >= burnRequestTime[msg.sender] + burnCooldownPeriod); // Vulnerable timestamp dependency
        require(balanceOf[msg.sender] >= burnRequests[msg.sender]);

        uint256 burnAmount = burnRequests[msg.sender];
        balanceOf[msg.sender] -= burnAmount;
        totalSupply -= burnAmount;

        // Clear burn request
        burnRequests[msg.sender] = 0;
        burnRequestTime[msg.sender] = 0;

        emit Burn(msg.sender, burnAmount);
        return true;
    }

    /**
     * Cancel pending burn request
     */
    function cancelBurn() public returns (bool success) {
        require(burnRequests[msg.sender] > 0);

        burnRequests[msg.sender] = 0;
        burnRequestTime[msg.sender] = 0;

        return true;
    }

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
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /**
     * Set allowance for other address and notify
     *
     * Allows `_spender` to spend no more than `_value` tokens on your behalf, and then ping the contract about it
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
