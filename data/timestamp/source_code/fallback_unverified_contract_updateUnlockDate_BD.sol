/*
 * ===== SmartInject Injection Details =====
 * Function      : updateUnlockDate
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
 * This function introduces a timestamp dependence vulnerability through a multi-transaction process. The vulnerability requires: 1) First transaction to initiate date change request, 2) Wait for supposed 24-hour period, 3) Second transaction to confirm the change. The vulnerability lies in the reliance on block.timestamp (now) which can be manipulated by miners within a ~900 second window, allowing attackers to potentially bypass the intended 24-hour waiting period through timestamp manipulation across multiple transactions.
 */
pragma solidity ^0.4.10;
contract Token {
    uint256 public totalSupply;
    function balanceOf(address _owner) constant returns (uint256 balance);
    function transfer(address _to, uint256 _value) returns (bool success);
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success);
    function approve(address _spender, uint256 _value) returns (bool success);
    function allowance(address _owner, address _spender) constant returns (uint256 remaining);
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}


/*  ERC 20 token */
contract StandardToken is Token {

    function transfer(address _to, uint256 _value) returns (bool success) {
      if (balances[msg.sender] >= _value && _value > 0) {
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
      } else {
        return false;
      }
    }

    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
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

    function balanceOf(address _owner) constant returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
      return allowed[_owner][_spender];
    }

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
}
// requires 300,000,000 INDI deposited here
contract INDISafe {
  mapping (address => uint256) allocations;
  uint256 public unlockDate;
  address public INDI;
  uint256 public constant exponent = 10**18;
  
  // Fix: moved storage declarations out of constructor and removed 'public' from mapping
  mapping (address => uint256) dateChangeRequests;
  uint256 public pendingUnlockDate;
  bool public dateChangeInProgress;

  function INDISafe() {
    INDI = 0xe8c09672cfb9cfce6e2edbb01057d9fa569f97c1;
    unlockDate = 1515283200;
    allocations[0x91c594706246Bed9a99CB49718b95D0F067042C8] = 300000000; 
  }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    function updateUnlockDate(uint256 _newUnlockDate) external {
        require(_newUnlockDate > now, "New unlock date must be in the future");
        require(_newUnlockDate != unlockDate, "New date must be different from current");
        
        // If this is the first request or a different date, reset the process
        if (!dateChangeInProgress || _newUnlockDate != pendingUnlockDate) {
            dateChangeInProgress = true;
            pendingUnlockDate = _newUnlockDate;
            dateChangeRequests[msg.sender] = now;
        } else {
            // If same date is requested again, check if enough time has passed
            require(dateChangeRequests[msg.sender] > 0, "Must initiate date change first");
            require(now >= dateChangeRequests[msg.sender] + 24 hours, "Must wait 24 hours between requests");
            
            // Vulnerable: relies on block.timestamp which can be manipulated
            // Also creates a race condition in multi-step process
            unlockDate = pendingUnlockDate;
            dateChangeInProgress = false;
            
            // Reset all requests
            dateChangeRequests[msg.sender] = 0;
        }
    }
    // === END FALLBACK INJECTION ===

  function unlock() external {
    if(now < unlockDate) revert();
    uint256 entitled = allocations[msg.sender];
    allocations[msg.sender] = 0;
    if(!StandardToken(INDI).transfer(msg.sender, entitled * exponent)) revert();
  }

}
