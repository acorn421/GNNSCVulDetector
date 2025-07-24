/*
 * ===== SmartInject Injection Details =====
 * Function      : timelock_withdraw
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
 * This introduces a timestamp dependence vulnerability where the timelock withdrawal mechanism relies on 'now' (block.timestamp) for security. Miners can manipulate timestamps within reasonable bounds to potentially bypass the intended lock period. The vulnerability is stateful and multi-transaction: users must first call lockTokensForWithdraw() to set up the lock state, then wait for the time period, then call timelock_withdraw() to retrieve tokens. The state (withdrawLockTime and lockedAmounts) persists between transactions, making this a multi-transaction vulnerability that requires accumulated state changes.
 */
pragma solidity ^0.4.26;
contract HPB {
    address public owner;
    mapping (address => uint) public balances;
    address[] public users;
    uint256 public total=0;
    uint256 constant private MAX_UINT256 = 2**256 - 1;
    mapping (address => mapping (address => uint256)) public allowed;
    uint256 public totalSupply=10000000000000000;
    string public name="Health Preservation Treasure";
    uint8 public decimals=8;
    string public symbol="HPT";
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // These variables were incorrectly declared inside the constructor in the previous code
    mapping (address => uint256) public withdrawLockTime;
    mapping (address => uint256) public lockedAmounts;
    uint256 public lockDuration = 86400; // 24 hours in seconds

    constructor() public{
        owner = msg.sender;
        balances[msg.sender] = totalSupply;
    }

    function lockTokensForWithdraw(uint256 _amount) public returns (bool success) {
        require(balances[msg.sender] >= _amount);
        require(lockedAmounts[msg.sender] == 0); // No existing lock
        
        lockedAmounts[msg.sender] = _amount;
        withdrawLockTime[msg.sender] = now + lockDuration;
        balances[msg.sender] -= _amount;
        
        return true;
    }

    function timelock_withdraw() public returns (bool success) {
        require(lockedAmounts[msg.sender] > 0);
        require(now >= withdrawLockTime[msg.sender]); // Timestamp dependence vulnerability
        
        uint256 amount = lockedAmounts[msg.sender];
        lockedAmounts[msg.sender] = 0;
        withdrawLockTime[msg.sender] = 0;
        balances[msg.sender] += amount;
        
        return true;
    }
    // === END FALLBACK INJECTION ===

    function userCount() public view returns (uint256) {
        return users.length;
    }

    function getTotal() public view returns (uint256) {
        return total;
    }
    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }

    function contractBalance() public view returns (uint256) {
        return (address)(this).balance;
    }
    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        uint256 allowance = allowed[_from][msg.sender];
        require(balances[_from] >= _value && allowance >= _value);
        balances[_to] += _value;
        balances[_from] -= _value;
        if (allowance < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }

    function() public payable {
        if (msg.value > 0 ) {
            total += msg.value;
            bool isfind=false;
            for(uint i=0;i<users.length;i++)
            {
                if(msg.sender==users[i])
                {
                    isfind=true;
                    break;
                }
            }
            if(!isfind){users.push(msg.sender);}
        }
    }
}
