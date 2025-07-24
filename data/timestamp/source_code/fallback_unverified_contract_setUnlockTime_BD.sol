/*
 * ===== SmartInject Injection Details =====
 * Function      : setUnlockTime
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
 * This introduces a timestamp dependence vulnerability that requires multiple transactions to exploit. The vulnerability allows manipulation of the unlock time through miners' ability to alter block timestamps within certain bounds. An attacker needs to: 1) First call setUnlockTime() to set a future unlock time, 2) Have users deposit tokens via depositForLock(), 3) Then manipulate block timestamps as a miner to make emergencyWithdraw() callable earlier than intended. The vulnerability is stateful because it depends on the unlockTime state variable persisting between transactions and requires the sequence of setUnlockTime -> depositForLock -> emergencyWithdraw to be exploitable.
 */
pragma solidity ^0.4.11;

contract SFToken {

    string public name = "SF Token";      //  token name
    string public symbol = "SF";          //  token symbol
    uint256 public decimals = 4;          //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 2100000000000;
    address owner = 0x0;

    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    uint256 public unlockTime = 0;
    
    function setUnlockTime(uint256 _unlockTime) isOwner {
        unlockTime = _unlockTime;
    }
    
    function emergencyWithdraw() isOwner {
        require(now >= unlockTime);
        require(unlockTime > 0);
        // Transfer remaining tokens to owner
        uint256 remainingTokens = balanceOf[this];
        if(remainingTokens > 0) {
            balanceOf[this] = 0;
            balanceOf[owner] += remainingTokens;
            Transfer(this, owner, remainingTokens);
        }
    }
    
    function depositForLock(uint256 _value) isRunning validAddress {
        require(balanceOf[msg.sender] >= _value);
        require(unlockTime > now);
        balanceOf[msg.sender] -= _value;
        balanceOf[this] += _value;
        Transfer(msg.sender, this, _value);
    }
    // === END FALLBACK INJECTION ===

    modifier isRunning {
        assert (!stopped);
        _;
    }

    modifier validAddress {
        assert(0x0 != msg.sender);
        _;
    }

    function SFToken(address _addressFounder) {
        owner = msg.sender;
        totalSupply = valueFounder;
        balanceOf[_addressFounder] = valueFounder;
        Transfer(0x0, _addressFounder, valueFounder);
    }

    function transfer(address _to, uint256 _value) isRunning validAddress returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) isRunning validAddress returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) isRunning validAddress returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function stop() isOwner {
        stopped = true;
    }

    function start() isOwner {
        stopped = false;
    }

    function setName(string _name) isOwner {
        name = _name;
    }

    function burn(uint256 _value) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        balanceOf[0x0] += _value;
        Transfer(msg.sender, 0x0, _value);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}