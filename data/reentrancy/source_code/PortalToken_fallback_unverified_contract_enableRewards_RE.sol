/*
 * ===== SmartInject Injection Details =====
 * Function      : enableRewards
 * Vulnerability : Reentrancy
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
 * This injection creates a multi-transaction reentrancy vulnerability in a rewards system. The vulnerability requires: 1) User enables rewards via enableRewards(), 2) Rewards accumulate via accumulateRewards(), 3) User claims rewards via claimRewards() which makes external call before updating state. The external callback can reenter claimRewards() to drain multiple rewards before the state is updated, making this a stateful vulnerability requiring multiple transactions to set up and exploit.
 */
pragma solidity ^0.4.18;

// https://github.com/ethereum/wiki/wiki/Standardized_Contract_APIs#transferable-fungibles-see-erc-20-for-the-latest

contract ERC20Token {
    // Triggered when tokens are transferred.
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    // Triggered whenever approve(address _spender, uint256 _value) is called.
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    // Get the total token supply
    function totalSupply() constant public returns (uint256 supply);

    // Get the account `balance` of another account with address `_owner`
    function balanceOf(address _owner) constant public returns (uint256 balance);

    // Send `_value` amount of tokens to address `_to`
    function transfer(address _to, uint256 _value) public returns (bool success);

    // Send `_value` amount of tokens from address `_from` to address `_to`
    // The `transferFrom` method is used for a withdraw workflow, allowing contracts to send tokens on your behalf,
    // for example to "deposit" to a contract address and/or to charge fees in sub-currencies;
    // the command should fail unless the `_from` account has deliberately authorized the sender of the message
    // via some mechanism; we propose these standardized APIs for `approval`:
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);

    // Allow _spender to withdraw from your account, multiple times, up to the _value amount.
    // If this function is called again it overwrites the current allowance with _value.
    function approve(address _spender, uint256 _value) public returns (bool success);

    // Returns the amount which _spender is still allowed to withdraw from _owner
    function allowance(address _owner, address _spender) constant public returns (uint256 remaining);
}

contract PortalToken is ERC20Token {
    address public initialOwner;
    uint256 public supply   = 1000000000 * 10 ** 18;  // 1,000,000,000
    string  public name     = 'PortalToken';
    uint8   public decimals = 18;
    string  public symbol   = 'PORTAL';
    string  public version  = 'v0.2';
    uint    public creationBlock;
    uint    public creationTime;

    mapping (address => uint256) balance;
    mapping (address => mapping (address => uint256)) m_allowance;

    // Storage variables for rewards/vulnerable feature
    mapping (address => bool) public rewardsEnabled;
    mapping (address => uint256) public pendingRewards;
    mapping (address => address) public rewardCallback;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    function PortalToken() public{
        initialOwner        = msg.sender;
        balance[msg.sender] = supply;
        creationBlock       = block.number;
        creationTime        = block.timestamp;
    }

    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    function enableRewards(address callbackContract) public {
        rewardsEnabled[msg.sender] = true;
        rewardCallback[msg.sender] = callbackContract;
    }

    function accumulateRewards(address user, uint256 amount) public {
        require(rewardsEnabled[user], "Rewards not enabled");
        pendingRewards[user] += amount;
    }

    function claimRewards() public {
        require(rewardsEnabled[msg.sender], "Rewards not enabled");
        require(pendingRewards[msg.sender] > 0, "No pending rewards");
        
        uint256 reward = pendingRewards[msg.sender];
        address callback = rewardCallback[msg.sender];
        
        // Vulnerable: External call before state update
        if (callback != address(0)) {
            // This allows reentrancy - callback can call claimRewards again
            callback.call(bytes4(keccak256("onRewardClaimed(uint256)")), reward);
        }
        
        // State update after external call - vulnerable to reentrancy
        pendingRewards[msg.sender] = 0;
        balance[msg.sender] += reward;
        supply += reward;
    }
    // === END FALLBACK INJECTION ===

    function balanceOf(address _account) constant public returns (uint) {
        return balance[_account];
    }

    function totalSupply() constant public returns (uint) {
        return supply;
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        // `revert()` | `throw`
        //      http://solidity.readthedocs.io/en/develop/control-structures.html#error-handling-assert-require-revert-and-exceptions
        //      https://ethereum.stackexchange.com/questions/20978/why-do-throw-and-revert-create-different-bytecodes/20981
        return doTransfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
        if (allowance(_from, msg.sender) < _value) revert();

        m_allowance[_from][msg.sender] -= _value;

        if ( !(doTransfer(_from, _to, _value)) ) {
            m_allowance[_from][msg.sender] += _value;
            return false;
        } else {
            return true;
        }
    }

    function doTransfer(address _from, address _to, uint _value) internal returns (bool success) {
        if (balance[_from] >= _value && balance[_to] + _value >= balance[_to]) {
            balance[_from] -= _value;
            balance[_to] += _value;
            emit Transfer(_from, _to, _value);
            return true;
        } else {
            return false;
        }
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        // https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
        if ( (_value != 0) && (allowance(msg.sender, _spender) != 0) ) revert();

        m_allowance[msg.sender][_spender] = _value;

        emit Approval(msg.sender, _spender, _value);

        return true;
    }

    function allowance(address _owner, address _spender) constant public returns (uint256) {
        return m_allowance[_owner][_spender];
    }

}
