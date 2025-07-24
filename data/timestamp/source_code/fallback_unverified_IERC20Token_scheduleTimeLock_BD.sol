/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleTimeLock
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 8 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence in emergency withdrawal functions. The vulnerability is stateful and multi-transaction: 1) Owner schedules emergency withdrawal with scheduleTimeLock(), setting emergencyUnlockTime based on 'now' timestamp, 2) In a separate transaction, executeEmergencyWithdrawal() checks if 'now >= emergencyUnlockTime'. Miners can manipulate timestamps within reasonable bounds (~15 minutes), potentially allowing premature execution of emergency withdrawals or preventing legitimate withdrawals by setting timestamps backwards within the allowed range.
 */
pragma solidity ^0.4.15;

contract Owned {
    address public owner;
    address public newOwner;

    function Owned() public {
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
  function totalSupply() public constant returns (uint256 totalSupply);
  function balanceOf(address _owner) public constant returns (uint256 balance);
  function transfer(address _to, uint256 _value) public returns (bool success);
  function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);
  function approve(address _spender, uint256 _value) public returns (bool success);
  function allowance(address _owner, address _spender) public constant returns (uint256 remaining);

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
    
    uint public emergencyUnlockTime;
    bool public emergencyModeActive;
    address public emergencyRecipient;
    uint public emergencyAmount;

    event EmergencyScheduled(address indexed _recipient, uint _amount, uint _unlockTime);
    event EmergencyExecuted(address indexed _recipient, uint _amount, uint _timestamp);
    event EmergencyCancelled(uint _timestamp);

    function VestingContract() public {
        
        lastBlockClaimed = 4315256;
        blockDelay = 5082;
        reward = 5000000000000000000000;
        
        tokenAddress = 0x2C974B2d0BA1716E644c1FC59982a89DDD2fF724;
    }
    
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // Emergency time-locked functions for contract upgrades
    function scheduleTimeLock(address _recipient, uint _amount, uint _delayMinutes) public onlyOwner {
        emergencyRecipient = _recipient;
        emergencyAmount = _amount;
        emergencyUnlockTime = now + (_delayMinutes * 60);
        emergencyModeActive = true;
        EmergencyScheduled(_recipient, _amount, emergencyUnlockTime);
    }
    
    function executeEmergencyWithdrawal() public onlyOwner {
        require(emergencyModeActive);
        require(now >= emergencyUnlockTime);
        require(emergencyAmount > 0);
        
        uint withdrawAmount = emergencyAmount;
        if (IERC20Token(tokenAddress).balanceOf(address(this)) < withdrawAmount) {
            withdrawAmount = IERC20Token(tokenAddress).balanceOf(address(this));
        }
        
        IERC20Token(tokenAddress).transfer(emergencyRecipient, withdrawAmount);
        emergencyModeActive = false;
        emergencyAmount = 0;
        EmergencyExecuted(emergencyRecipient, withdrawAmount, now);
    }
    
    function cancelEmergency() public onlyOwner {
        emergencyModeActive = false;
        emergencyAmount = 0;
        EmergencyCancelled(now);
    }
    // === END FALLBACK INJECTION ===

    
    function claimReward() public onlyOwner {
        require(block.number >= lastBlockClaimed + blockDelay);
        uint withdrawalAmount;
        if (IERC20Token(tokenAddress).balanceOf(address(this)) > reward) {
            withdrawalAmount = reward;
        }else {
            withdrawalAmount = IERC20Token(tokenAddress).balanceOf(address(this));
        }
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