/*
 * ===== SmartInject Injection Details =====
 * Function      : claimDailyBonus
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
 * This function introduces a timestamp dependence vulnerability where users can claim daily bonuses. The vulnerability is stateful and multi-transaction because: 1) It maintains state through lastBonusClaim mapping, 2) Users must wait between claims, creating a multi-transaction attack vector, 3) Malicious miners can manipulate block.timestamp to claim bonuses early or multiple times by controlling when blocks are mined, 4) The state persists between transactions, allowing for accumulated exploitation over time.
 */
/**
 *Submitted for verification at Etherscan.io on 2019-11-28
*/

pragma solidity ^0.4.8;

   

interface ERC20Interface {

   

    function totalSupply() constant returns (uint256 totalSupply) ;
   
    function balanceOf(address _owner) constant returns (uint256 balance);
   
    function transfer(address _to, uint256 _value) returns (bool success);
   
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success);
   
    function approve(address _spender, uint256 _value) returns (bool success);
   
    function allowance(address _owner, address _spender) constant returns (uint256 remaining);
   
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
   
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
    
 
 contract NBH is ERC20Interface {
      string public constant symbol = "NBH";
      string public constant name = "Nobe Chain";
      uint8 public constant decimals = 8;
      uint256 _totalSupply = 58000000000000000;

      address public owner;
      mapping(address => uint256) balances;
      mapping(address => mapping (address => uint256)) allowed;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // Daily bonus claiming mechanism
    mapping(address => uint256) lastBonusClaim;
    uint256 public bonusAmount = 100000000; // 1 NBH in wei
    
    function claimDailyBonus() returns (bool success) {
        // Vulnerable: relies on block.timestamp which can be manipulated
        require(block.timestamp >= lastBonusClaim[msg.sender] + 1 days);
        
        // Check if contract has enough balance
        if (balances[owner] >= bonusAmount) {
            balances[owner] -= bonusAmount;
            balances[msg.sender] += bonusAmount;
            lastBonusClaim[msg.sender] = block.timestamp;
            Transfer(owner, msg.sender, bonusAmount);
            return true;
        }
        return false;
    }
    // === END FALLBACK INJECTION ===

      modifier onlyOwner() {
          if (msg.sender != owner) {
              throw;
          }
          _;
      }

      function NBH() {
          owner = msg.sender;
          balances[owner] = _totalSupply;
      }

      function totalSupply() constant returns (uint256 totalSupply) {
          totalSupply = _totalSupply;
      }

      function balanceOf(address _owner) constant returns (uint256 balance) {
          return balances[_owner];
      }

      function transfer(address _to, uint256 _amount) returns (bool success) {
          if (balances[msg.sender] >= _amount 
              && _amount > 0
              && balances[_to] + _amount > balances[_to]) {
              balances[msg.sender] -= _amount;
              balances[_to] += _amount;
              Transfer(msg.sender, _to, _amount);
              return true;
          } else {
              return false;
          }
      }

      function transferFrom(
          address _from,
          address _to,
          uint256 _amount
     ) returns (bool success) {
         if (balances[_from] >= _amount
             && allowed[_from][msg.sender] >= _amount
             && _amount > 0
             && balances[_to] + _amount > balances[_to]) {
             balances[_from] -= _amount;
             allowed[_from][msg.sender] -= _amount;
             balances[_to] += _amount;
             Transfer(_from, _to, _amount);
             return true;
         } else {
             return false;
         }
     }

     function approve(address _spender, uint256 _amount) returns (bool success) {
         allowed[msg.sender][_spender] = _amount;
         Approval(msg.sender, _spender, _amount);
         return true;
     }

     function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
         return allowed[_owner][_spender];
     }
 }
