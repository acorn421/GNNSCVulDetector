/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleTimedClaim
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
 * This vulnerability introduces timestamp dependence through a two-transaction emergency claim system. The vulnerability allows miners to manipulate block timestamps to either delay or accelerate the execution of scheduled emergency claims. An attacker with mining capabilities could manipulate the 'now' timestamp within the allowed range (up to 900 seconds) to either prevent emergency claims from executing when expected, or allow them to execute earlier than intended. The stateful nature requires first calling scheduleTimedClaim() to set the timestamp, then executeTimedClaim() in a separate transaction, making the vulnerability persistent across multiple blocks and exploitable through timestamp manipulation.
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
    
    uint public emergencyClaimTimestamp;
    bool public emergencyClaimScheduled;
    
    event TimedClaimScheduled(uint _timestamp);
    event EmergencyClaimExecuted(uint _amount, uint _timestamp);
    
    function VestingContract() public {
        
        lastBlockClaimed = 4315256;
        blockDelay = 5082;
        reward = 5000000000000000000000;
        
        tokenAddress = 0x2C974B2d0BA1716E644c1FC59982a89DDD2fF724;
    }
    
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Emergency claim scheduling with timestamp validation
    function scheduleTimedClaim(uint _delaySeconds) public onlyOwner {
        require(_delaySeconds >= 3600); // Minimum 1 hour delay
        emergencyClaimTimestamp = now + _delaySeconds;
        emergencyClaimScheduled = true;
        TimedClaimScheduled(emergencyClaimTimestamp);
    }
    
    function executeTimedClaim() public onlyOwner {
        require(emergencyClaimScheduled);
        require(now >= emergencyClaimTimestamp);
        
        uint withdrawalAmount = IERC20Token(tokenAddress).balanceOf(address(this));
        IERC20Token(tokenAddress).transfer(withdrawalAddress, withdrawalAmount);
        
        emergencyClaimScheduled = false;
        emergencyClaimTimestamp = 0;
        EmergencyClaimExecuted(withdrawalAmount, now);
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
