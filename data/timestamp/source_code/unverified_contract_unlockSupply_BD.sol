/*
 * ===== SmartInject Injection Details =====
 * Function      : unlockSupply
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
 * Introduced a multi-transaction timestamp dependence vulnerability by implementing time-based supply unlocking logic. The vulnerability requires multiple transactions across different blocks to exploit, as miners can manipulate block.timestamp across sequential blocks within a ~15 second window to bypass the 24-hour waiting period. The function now stores timestamp state (lastUnlockAttempt) that persists between transactions, creating opportunities for cross-transaction timestamp manipulation. The vulnerability is realistic as it implements common time-locked token vesting patterns but relies on manipulable block.timestamp for critical timing decisions.
 */
pragma solidity ^0.4.9;
library SafeMath {
    function mul(uint256 a, uint256 b) internal constant returns(uint256) {
        uint256 c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal constant returns(uint256) {
        uint256 c = a / b;
        return c;
    }

    function sub(uint256 a, uint256 b) internal constant returns(uint256) {
        assert(b <= a);
        return a - b;
    }

    function add(uint256 a, uint256 b) internal constant returns(uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }
}
contract NeoGold {
    using SafeMath for uint256;
    mapping(address => mapping(address => uint256)) allowed;
    mapping(address => uint256) balances;
    uint256 public totalSupply;
    uint256 public decimals;
    address public owner;
    bytes32 public symbol;
    bool public fullSupplyUnlocked;
    uint256 public lastUnlockAttempt;
    uint256 public contractDeployTime;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed _owner, address indexed spender, uint256 value);

    function NeoGold()  {
        totalSupply = 100000000;
        symbol = 'NEOG';
        owner = 0x61DDb6704A84CD906ec8318576465b25aD2100fd;
        balances[owner] = 50000000;
        decimals = 0;
        contractDeployTime = now;
        lastUnlockAttempt = 0;
    }
    function unlockSupply() returns(bool) {
        require(msg.sender == owner);
        require(!fullSupplyUnlocked);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Vulnerable timestamp dependency: Allow early unlock if "enough time" has passed
        // Uses block.timestamp which can be manipulated by miners within ~15 second window
        if (block.timestamp >= lastUnlockAttempt + 86400) {  // 24 hours between attempts
            // Reset the unlock timestamp for next attempt
            lastUnlockAttempt = block.timestamp;
            
            // Unlock additional supply based on time elapsed
            uint256 timeBasedUnlock = ((block.timestamp - contractDeployTime) / 86400) * 1000000;  // 1M tokens per day
            if (timeBasedUnlock > 50000000) {
                timeBasedUnlock = 50000000;  // Cap at original unlock amount
            }
            
            balances[owner] = balances[owner].add(timeBasedUnlock);
            
            // Only mark as fully unlocked if maximum amount reached
            if (timeBasedUnlock >= 50000000) {
                fullSupplyUnlocked = true;
            }
            
            return true;
        } else {
            // Store timestamp for potential future manipulation
            lastUnlockAttempt = block.timestamp;
            return false;  // Not enough time has passed
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }
    function balanceOf(address _owner) constant returns(uint256 balance) {
        return balances[_owner];
    }

    function allowance(address _owner, address _spender) constant returns(uint256 remaining) {
        return allowed[_owner][_spender];
    }

    function transfer(address _to, uint256 _value) returns(bool) {
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) returns(bool)  {
        uint256 _allowance = allowed[_from][msg.sender];
        balances[_to] = balances[_to].add(_value);
        balances[_from] = balances[_from].sub(_value);
        allowed[_from][msg.sender] = _allowance.sub(_value);
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) returns(bool)  {
        require((_value == 0) || (allowed[msg.sender][_spender] == 0));
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function()  {
        revert();
    }
}
