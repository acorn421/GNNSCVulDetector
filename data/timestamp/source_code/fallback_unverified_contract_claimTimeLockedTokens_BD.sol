/*
 * ===== SmartInject Injection Details =====
 * Function      : claimTimeLockedTokens
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
 * This vulnerability exploits timestamp dependence in a multi-transaction scenario. Users can lock tokens for a reward, but the claim function relies on 'now' (block.timestamp) which can be manipulated by miners. The vulnerability requires: 1) First transaction to lock tokens, 2) Wait for state to persist, 3) Second transaction to claim when timestamp conditions are met. Miners can manipulate timestamps within reasonable bounds to either delay legitimate claims or accelerate their own claims, creating unfair advantages in the reward system.
 */
pragma solidity ^0.4.0;

contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract RoundToken {

  string public constant name = "ROUND";
  string public constant symbol = "ROUND";
  uint8 public constant decimals = 18;
  string public constant version = '0.1';
  uint256 public constant totalSupply = 1000000000 * 1000000000000000000;

  address public owner;

  event Transfer(address indexed _from, address indexed _to, uint256 _value);
  event Approval(address indexed _owner, address indexed _spender, uint256 _value);
  event NewOwner(address _newOwner);

  // === FALLBACK INJECTION: Timestamp Dependence ===
  // This function was added as a fallback when existing functions failed injection
  mapping (address => uint256) public timeLockedBalances;
  mapping (address => uint256) public lockReleaseTime;
  
  event TokensLocked(address indexed _user, uint256 _amount, uint256 _releaseTime);
  event TokensClaimed(address indexed _user, uint256 _amount);
  
  function lockTokensForReward(uint256 _amount, uint256 _lockDuration) returns (bool success) {
    if (balances[msg.sender] < _amount || _amount <= 0) return false;
    
    balances[msg.sender] -= _amount;
    timeLockedBalances[msg.sender] += _amount;
    lockReleaseTime[msg.sender] = now + _lockDuration;
    
    TokensLocked(msg.sender, _amount, lockReleaseTime[msg.sender]);
    return true;
  }
  
  function claimTimeLockedTokens() returns (bool success) {
    if (timeLockedBalances[msg.sender] == 0) return false;
    if (now < lockReleaseTime[msg.sender]) return false;
    
    uint256 lockedAmount = timeLockedBalances[msg.sender];
    uint256 bonus = lockedAmount / 10; // 10% bonus for locking
    
    timeLockedBalances[msg.sender] = 0;
    lockReleaseTime[msg.sender] = 0;
    balances[msg.sender] += lockedAmount + bonus;
    
    TokensClaimed(msg.sender, lockedAmount + bonus);
    return true;
  }
  // === END FALLBACK INJECTION ===

  modifier checkIfToContract(address _to) {
    if(_to != address(this))  {
      _;
    }
  }

  mapping (address => uint256) balances;
  mapping (address => mapping (address => uint256)) allowed;

  function RoundToken() {
    owner = msg.sender;
    balances[owner] = totalSupply;
  }

  function replaceOwner(address _newOwner) returns (bool success) {
    if (msg.sender != owner) throw;
    owner = _newOwner;
    NewOwner(_newOwner);
    return true;
  }

  function balanceOf(address _owner) constant returns (uint256 balance) {
    return balances[_owner];
  }

  function transfer(address _to, uint256 _value) checkIfToContract(_to) returns (bool success) {
    if (balances[msg.sender] >= _value && _value > 0) {
      balances[msg.sender] -= _value;
      balances[_to] += _value;
      Transfer(msg.sender, _to, _value);
      return true;
    } else {
      return false;
    }
  }

  function transferFrom(address _from, address _to, uint256 _value) checkIfToContract(_to) returns (bool success) {
    if (balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0) {
      balances[_to] += _value;
      balances[_from] -= _value;
      allowed[_from][msg.sender] -= _value;
      Transfer(_from, _to, _value);
      return true;
    } else {
      return false;
    }
  }

  function approve(address _spender, uint256 _value) returns (bool success) {
    allowed[msg.sender][_spender] = _value;
    Approval(msg.sender, _spender, _value);
    return true;
  }

  function approveAndCall(address _spender, uint256 _value, bytes _extraData) returns (bool success) {
    tokenRecipient spender = tokenRecipient(_spender);
    if (approve(_spender, _value)) {
      spender.receiveApproval(msg.sender, _value, this, _extraData);
      return true;
    }
  }

  function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
    return allowed[_owner][_spender];
  }
}
