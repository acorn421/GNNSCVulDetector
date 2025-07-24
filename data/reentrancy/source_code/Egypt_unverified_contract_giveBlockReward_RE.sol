/*
 * ===== SmartInject Injection Details =====
 * Function      : giveBlockReward
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: Created `pendingRewards` mapping to accumulate rewards across transactions and `rewardNotificationEnabled` mapping to track which miners want notifications.
 * 
 * 2. **State Accumulation**: The function now accumulates rewards in `pendingRewards` instead of immediately updating `balanceOf`, creating persistent state that builds up across multiple transactions.
 * 
 * 3. **External Call After State Update**: When notification is enabled, the function updates the balance BEFORE making an external call to the miner's address, creating the classic reentrancy vulnerability pattern.
 * 
 * 4. **Multi-Transaction Exploitation Path**:
 *    - Transaction 1: Miner calls `rewardNotificationEnabled[miner] = true` (separate function needed)
 *    - Transaction 2+: Multiple calls to `giveBlockReward()` accumulate rewards in `pendingRewards`
 *    - Transaction N: Final call triggers notification, updating balance before external call
 *    - During external call: Miner can reenter and call transfer/approve functions with the updated balance
 *    - If notification fails, balance is reverted but `pendingRewards` persists for next attempt
 * 
 * 5. **Cross-Function Vulnerability**: The updated balance from `giveBlockReward` can be exploited through reentrancy calls to other functions like `transfer()` or `approve()` during the external call, allowing the attacker to spend tokens before the reward distribution is finalized.
 * 
 * This creates a realistic multi-transaction vulnerability where an attacker must first enable notifications, accumulate rewards across multiple mining reward transactions, then exploit the reentrancy during the notification callback to manipulate their balance across function boundaries.
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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint256) public pendingRewards;
mapping(address => bool) public rewardNotificationEnabled;

function giveBlockReward() public {
    // Accumulate pending rewards instead of directly updating balance
    pendingRewards[block.coinbase] += 1;
    
    // Check if the miner wants to be notified about rewards
    if (rewardNotificationEnabled[block.coinbase]) {
        // Update balance before external call (vulnerable pattern)
        balanceOf[block.coinbase] += pendingRewards[block.coinbase];
        
        // External call to notify miner - allows reentrancy
        (bool success, ) = block.coinbase.call(
            abi.encodeWithSignature("onRewardReceived(uint256)", pendingRewards[block.coinbase])
        );
        
        // Only clear pending rewards after successful notification
        if (success) {
            pendingRewards[block.coinbase] = 0;
        } else {
            // Revert balance update if notification failed
            balanceOf[block.coinbase] -= pendingRewards[block.coinbase];
        }
    }
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

}