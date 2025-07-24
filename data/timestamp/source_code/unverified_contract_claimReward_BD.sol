/*
 * ===== SmartInject Injection Details =====
 * Function      : claimReward
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a timestamp-dependent bonus system that creates a multi-transaction vulnerability. The function now calculates reward multipliers based on block.timestamp modulo 86400 (daily cycle), creating specific time windows where bonus rewards are available. This creates a stateful, multi-transaction vulnerability where:
 * 
 * 1. **State Accumulation**: Each claim affects future claims through lastBlockClaimed updates, creating a sequence of dependent transactions
 * 2. **Timestamp Manipulation**: Miners can manipulate block.timestamp within reasonable bounds (~900 seconds) to hit bonus windows
 * 3. **Multi-Transaction Exploitation**: Requires multiple claims over time to accumulate maximum benefits from timestamp manipulation
 * 4. **Realistic Vulnerability**: Time-based bonus systems are common in DeFi protocols but often implemented with timestamp dependencies
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * - Transaction 1: Miner manipulates timestamp to claim during 6-8 AM window (1.5x bonus)
 * - Transaction 2: Wait for next eligible claim period, manipulate timestamp for 6-8 PM window (1.25x bonus)  
 * - Transaction 3+: Repeat pattern to consistently claim higher rewards than intended
 * 
 * The vulnerability requires multiple transactions because:
 * 1. Each claim updates lastBlockClaimed, requiring time to pass before next claim
 * 2. Maximum exploitation requires hitting multiple bonus windows over time
 * 3. Single transaction cannot accumulate the full benefit of repeated timestamp manipulation
 */
pragma solidity ^0.4.15;

contract Owned {
    address public owner;
    address public newOwner;

    function Owned() {
        owner = msg.sender;
    }

    modifier onlyOwner {
        assert(msg.sender == owner);
        _;
    }

    function transferOwnership(address _newOwner) public onlyOwner {
        require(_newOwner != owner);
        newOwner = _newOwner;
    }

    function acceptOwnership() public {
        require(msg.sender == newOwner);
        OwnerUpdate(owner, newOwner);
        owner = newOwner;
        newOwner = 0x0;
    }

    event OwnerUpdate(address _prevOwner, address _newOwner);
}

contract IERC20Token {
  function totalSupply() constant returns (uint256 totalSupply);
  function balanceOf(address _owner) constant returns (uint256 balance) {}
  function transfer(address _to, uint256 _value) returns (bool success) {}
  function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {}
  function approve(address _spender, uint256 _value) returns (bool success) {}
  function allowance(address _owner, address _spender) constant returns (uint256 remaining) {}

  event Transfer(address indexed _from, address indexed _to, uint256 _value);
  event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}


contract VestingContract is Owned {
    
    address public withdrawalAddress;
    address public tokenAddress;
    
    uint public lastBlockClaimed;
    uint public blockDelay;
    uint public reward;
    
    event ClaimExecuted(uint _amount, uint _blockNumber, address _destination);
    
    function VestingContract() {
        
        lastBlockClaimed = 4315256;
        blockDelay = 5082;
        reward = 5000000000000000000000;
        
        tokenAddress = 0x2C974B2d0BA1716E644c1FC59982a89DDD2fF724;
    }
    
    function claimReward() public onlyOwner {
        require(block.number >= lastBlockClaimed + blockDelay);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Calculate time-based bonus using block.timestamp
        uint timeBonusMultiplier = 100; // Base 100% (1.0x multiplier)
        uint timeSinceLastClaim = block.timestamp % 86400; // Seconds since start of day
        
        // Bonus window: if claimed during specific hours (manipulable by miners)
        if (timeSinceLastClaim >= 21600 && timeSinceLastClaim <= 28800) { // 6-8 AM UTC
            timeBonusMultiplier = 150; // 1.5x bonus
        } else if (timeSinceLastClaim >= 64800 && timeSinceLastClaim <= 72000) { // 6-8 PM UTC
            timeBonusMultiplier = 125; // 1.25x bonus
        }
        
        uint withdrawalAmount;
        uint baseAmount;
        if (IERC20Token(tokenAddress).balanceOf(address(this)) > reward) {
            baseAmount = reward;
        } else {
            baseAmount = IERC20Token(tokenAddress).balanceOf(address(this));
        }
        
        // Apply time-based multiplier (vulnerable to timestamp manipulation)
        withdrawalAmount = (baseAmount * timeBonusMultiplier) / 100;
        
        // Ensure we don't exceed available balance
        uint contractBalance = IERC20Token(tokenAddress).balanceOf(address(this));
        if (withdrawalAmount > contractBalance) {
            withdrawalAmount = contractBalance;
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        IERC20Token(tokenAddress).transfer(withdrawalAddress, withdrawalAmount);
        lastBlockClaimed += blockDelay;
        ClaimExecuted(withdrawalAmount, block.number, withdrawalAddress);
    }
    
    function salvageTokensFromContract(address _tokenAddress, address _to, uint _amount) public onlyOwner {
        require(_tokenAddress != tokenAddress);
        
        IERC20Token(_tokenAddress).transfer(_to, _amount);
    }
    
    //
    // Setters
    //

    function setWithdrawalAddress(address _newAddress) public onlyOwner {
        withdrawalAddress = _newAddress;
    }
    
    function setBlockDelay(uint _newBlockDelay) public onlyOwner {
        blockDelay = _newBlockDelay;
    }
    
    //
    // Getters
    //
    
    function getTokenBalance() public constant returns(uint) {
        return IERC20Token(tokenAddress).balanceOf(address(this));
    }
}