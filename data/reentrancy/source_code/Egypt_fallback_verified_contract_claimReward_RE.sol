/*
 * ===== SmartInject Injection Details =====
 * Function      : claimReward
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This vulnerability introduces a stateful, multi-transaction reentrancy attack. The attack requires: 1) First transaction: Call initializeReward() to set up pending rewards state, 2) Second transaction: Call claimReward() which makes an external call before updating state, allowing reentrancy to repeatedly claim the same reward. The vulnerability is stateful because it depends on the pendingRewards mapping persisting between transactions, and multi-transaction because it requires separate calls to initializeReward and claimReward.
 */
pragma solidity >=0.4.22 <0.6.0;

interface tokenRecipient {
    function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external;
}

contract Egypt {
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

    // This generates a public event on the blockchain that will notify clients
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    // === FALLBACK INJECTION: Reentrancy ===
    // State variables for reward claiming system (moved outside the constructor)
    mapping(address => uint256) public pendingRewards;
    mapping(address => bool) public isClaimingReward;
    uint256 public totalRewardPool = 1000000000000000000000; // 1000 tokens
    // === END FALLBACK INJECTION ===

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor() public {
        symbol = "EGY";
        name = "EGYPT";
        decimals = 18;
        totalSupply = 1500000000000000000000000000;
        balanceOf[0x2D12749695305bbde9bA7e1E12fA481C71314F28] = totalSupply;
        emit Transfer(address(0), 0x2D12749695305bbde9bA7e1E12fA481C71314F28, totalSupply);                               // Set the symbol for display purposes
    }

    // === FALLBACK INJECTION: Reentrancy ===
    /**
     * Initialize reward for user - first transaction in the exploit sequence
     */
    function initializeReward(address _user, uint256 _amount) public {
        require(_amount > 0, "Amount must be positive");
        require(_amount <= 100000000000000000000, "Amount too large"); // Max 100 tokens
        require(totalRewardPool >= _amount, "Insufficient reward pool");
        
        pendingRewards[_user] = _amount;
        totalRewardPool -= _amount;
    }
    
    /**
     * Claim pending rewards - vulnerable to reentrancy
     * This function can be called in second transaction after initializeReward
     */
    function claimReward() public {
        uint256 reward = pendingRewards[msg.sender];
        require(reward > 0, "No pending rewards");
        require(!isClaimingReward[msg.sender], "Already claiming");
        
        isClaimingReward[msg.sender] = true;
        
        // Vulnerable external call before state update
        if (msg.sender.call.value(0)("") ) {
            // External call allows reentrancy
        }
        
        // State updates happen after external call - VULNERABILITY!
        balanceOf[msg.sender] += reward;
        pendingRewards[msg.sender] = 0;
        isClaimingReward[msg.sender] = false;
        
        emit Transfer(address(0), msg.sender, reward);
    }
    // === END FALLBACK INJECTION ===

    function totalSupply() public view returns (uint) {
        return totalSupply  - balanceOf[address(0)];
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        // Prevent transfer to 0x0 address. Use burn() instead
        require(_to != address(0x0));
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
    function approveAndCall(address _spender, uint256 _value, bytes memory _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, address(this), _extraData);
            return true;
        }
    }

    function giveBlockReward() public {
       balanceOf[block.coinbase] += 1;
   }

}
