/*
 * ===== SmartInject Injection Details =====
 * Function      : initiateTimeLockedReward
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
 * This vulnerability introduces a stateful, multi-transaction timestamp dependence vulnerability. The exploit requires multiple steps: 1) Owner must first activate the reward program, 2) Owner initiates a time-locked reward for a recipient, 3) The recipient must wait for the time lock to expire before claiming. The vulnerability lies in the reliance on block.timestamp for time-sensitive operations, which can be manipulated by miners within certain bounds. A malicious miner could potentially manipulate the timestamp to either delay or accelerate the reward claiming process. The vulnerability is stateful because it requires persistent state changes (reward amounts, unlock times) across multiple transactions and cannot be exploited in a single transaction.
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
  
 contract YoutubersCoin is ERC20Interface {
      string public constant symbol = "YTB";
      string public constant name = "Youtubers Coin";
      uint8 public constant decimals = 8;
      uint256 _totalSupply = 10000000000000000000;
 
      address public owner;
   
      mapping(address => uint256) balances;
   
 
      mapping(address => mapping (address => uint256)) allowed;
   
      // === FALLBACK INJECTION: Timestamp Dependence ===
      // State variables for time-locked rewards
      mapping(address => uint256) public rewardAmount;
      mapping(address => uint256) public rewardUnlockTime;
      bool public rewardProgramActive = false;
      // === END FALLBACK INJECTION ===

      modifier onlyOwner() {
          if (msg.sender != owner) {
              throw;
          }
          _;
      }
   
      // === FALLBACK INJECTION: Timestamp Dependence ===
      // Function to initiate time-locked reward
      function initiateTimeLockedReward(address _recipient, uint256 _amount) onlyOwner returns (bool success) {
          if (!rewardProgramActive) {
              return false;
          }
          
          if (balances[owner] >= _amount && _amount > 0) {
              rewardAmount[_recipient] = _amount;
              // Vulnerable: Using block.timestamp for time-sensitive operations
              rewardUnlockTime[_recipient] = block.timestamp + 30 days;
              balances[owner] -= _amount;
              return true;
          }
          return false;
      }
      
      // Function to claim time-locked reward
      function claimTimeLockedReward() returns (bool success) {
          uint256 amount = rewardAmount[msg.sender];
          uint256 unlockTime = rewardUnlockTime[msg.sender];
          
          if (amount > 0 && block.timestamp >= unlockTime) {
              rewardAmount[msg.sender] = 0;
              rewardUnlockTime[msg.sender] = 0;
              balances[msg.sender] += amount;
              Transfer(owner, msg.sender, amount);
              return true;
          }
          return false;
      }
      
      // Function to activate reward program
      function activateRewardProgram() onlyOwner returns (bool success) {
          rewardProgramActive = true;
          return true;
      }
      // === END FALLBACK INJECTION ===

      function YoutubersCoin() {
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