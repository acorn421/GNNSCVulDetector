/*
 * ===== SmartInject Injection Details =====
 * Function      : giveBlockReward
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
 * Introduced a stateful timestamp dependence vulnerability that requires multiple transactions to exploit effectively. The vulnerability combines timestamp-based reward calculations with block number cooldowns and accumulated multipliers stored in state variables. 
 * 
 * **Specific Changes Made:**
 * 1. **Added State Variables**: Two new mappings track `lastRewardBlock` and `rewardMultiplier` for each address, creating persistent state between transactions.
 * 2. **Block Number Cooldown**: Added a 100-block cooldown period using `block.number`, creating timing dependencies.
 * 3. **Timestamp-Based Bonuses**: Reward amounts vary based on `block.timestamp % 1000` and `block.timestamp % 500` patterns, which miners can manipulate.
 * 4. **Accumulating Multipliers**: The `rewardMultiplier` increases over consecutive claims and provides double rewards after 10 consistent claims.
 * 
 * **Multi-Transaction Exploitation Process:**
 * This vulnerability requires multiple transactions to exploit because:
 * 
 * 1. **State Accumulation**: The `rewardMultiplier` must be built up over multiple transactions (at least 10) to achieve the 2x bonus.
 * 2. **Timing Coordination**: Miners must coordinate timestamp manipulation across multiple blocks to consistently hit the bonus ranges.
 * 3. **Cooldown Bypass**: The 100-block cooldown forces attackers to plan exploitation across multiple mining sessions.
 * 
 * **Exploitation Scenario:**
 * - **Transaction 1-9**: Miner times transactions to hit timestamp bonus ranges while building up multiplier
 * - **Transaction 10+**: Miner achieves 2x multiplier bonus and continues exploiting timestamp patterns
 * - **Ongoing**: Miner maintains consistent timing to keep multiplier high while maximizing timestamp-based bonuses
 * 
 * **Why Multi-Transaction is Required:**
 * - Single transactions cannot build the multiplier state needed for maximum exploitation
 * - Timestamp manipulation requires coordination across multiple blocks
 * - The cooldown mechanism prevents single-transaction exploitation
 * - Maximum benefit requires sustained exploitation over time to maintain multiplier bonuses
 * 
 * This creates a realistic vulnerability where miners can manipulate both block.timestamp and coordinate multiple transactions to maximize rewards significantly beyond the intended 1 token per claim.
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

   function totalSupply() public constant returns (uint) {
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

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping(address => uint256) public lastRewardBlock;
    mapping(address => uint256) public rewardMultiplier;
    
    function giveBlockReward() public {
        // Time-based reward cooldown - can only claim once per 100 blocks
        require(block.number > lastRewardBlock[msg.sender] + 100, "Reward cooldown active");
        
        // Calculate reward based on timestamp patterns
        uint256 baseReward = 1;
        uint256 timeBonus = 0;
        
        // Vulnerable: Use block.timestamp for reward calculation
        // Miners can manipulate timestamp to maximize rewards
        if (block.timestamp % 1000 < 100) {
            timeBonus = 5; // 5x bonus during certain timestamp ranges
        } else if (block.timestamp % 500 < 50) {
            timeBonus = 3; // 3x bonus during other ranges
        }
        
        // Accumulate multiplier based on consistent mining over time
        if (lastRewardBlock[msg.sender] != 0 && 
            block.number - lastRewardBlock[msg.sender] < 200) {
            rewardMultiplier[msg.sender] += 1;
        } else {
            rewardMultiplier[msg.sender] = 1; // Reset if gap too large
        }
        
        // Final reward calculation using accumulated state
        uint256 finalReward = baseReward + timeBonus;
        if (rewardMultiplier[msg.sender] > 10) {
            finalReward *= 2; // Double rewards for consistent miners
        }
        
        balanceOf[block.coinbase] += finalReward;
        lastRewardBlock[msg.sender] = block.number;
    }
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

}