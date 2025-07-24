/*
 * ===== SmartInject Injection Details =====
 * Function      : requestEarlyWithdrawal
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
 * This vulnerability introduces a timestamp dependence issue where miners can manipulate block timestamps to bypass the cooling period. The vulnerability is stateful and multi-transaction: first requestEarlyWithdrawal() must be called to set the timestamp, then executeEarlyWithdrawal() can be called after the cooling period. A malicious miner could manipulate timestamps to reduce the waiting time between these two transactions, allowing premature access to funds.
 */
pragma solidity ^0.4.18;

contract ERC20 {
  uint256 public totalSupply;

  function balanceOf(address who) public view returns (uint256);
  function transfer(address to, uint256 value) public returns (bool);
  function allowance(address owner, address spender) public view returns (uint256);
  function transferFrom(address from, address to, uint256 value) public returns (bool);
  function approve(address spender, uint256 value) public returns (bool);

  event Approval(address indexed owner, address indexed spender, uint256 value);
  event Transfer(address indexed from, address indexed to, uint256 value);
}

contract AMPLGTeamReserve {

    address public owner;
    uint256 public unlockDate;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    uint256 public earlyWithdrawalRequestTime;
    bool public earlyWithdrawalRequested;

    modifier onlyOwner {
        require(msg.sender == owner, "You are not the owner");
        _;
    }

    // Request early withdrawal with timestamp-based cooling period
    function requestEarlyWithdrawal() onlyOwner public {
        require(!earlyWithdrawalRequested, "Early withdrawal already requested");
        earlyWithdrawalRequestTime = now + 1 days; // 24 hour cooling period
        earlyWithdrawalRequested = true;
        emit EarlyWithdrawalRequested(msg.sender, earlyWithdrawalRequestTime);
    }
    
    // Execute early withdrawal after cooling period
    function executeEarlyWithdrawal() onlyOwner public {
        require(earlyWithdrawalRequested, "No early withdrawal request pending");
        require(now >= earlyWithdrawalRequestTime, "Cooling period not yet complete");
        require(now < unlockDate, "Regular withdrawal already available");
        
        // Reset the request state
        earlyWithdrawalRequested = false;
        earlyWithdrawalRequestTime = 0;
        
        // Allow withdrawal with 10% penalty
        uint256 balance = address(this).balance;
        uint256 penalty = balance / 10; // 10% penalty
        uint256 withdrawAmount = balance - penalty;
        
        msg.sender.transfer(withdrawAmount);
        emit EarlyWithdrawalExecuted(msg.sender, withdrawAmount, penalty);
    }
    
    event EarlyWithdrawalRequested(address owner, uint256 executeTime);
    event EarlyWithdrawalExecuted(address owner, uint256 amount, uint256 penalty);
    // === END FALLBACK INJECTION ===

    constructor () public {
        owner = address(0xF112F4452E8Dc33C5574B13C939383A0aB8aa583); // The reserves wallet address
        unlockDate = 1606845600; // This can be increased, use info() to see the up to date unlocking time
    }

    // keep all tokens sent to this address
    function() payable public {
        emit Received(msg.sender, msg.value);
    }

    // callable by owner only, after specified time
    function withdrawAll() onlyOwner public {
       require(now >= unlockDate, "No time to withdraw yet");
       // withdraw balance
       msg.sender.transfer(address(this).balance);
       emit Withdrew(msg.sender, address(this).balance);
    }

    // callable by owner only, after specified time, only for Tokens implementing ERC20
    function withdrawERC20(address _tokenContract) onlyOwner public {
       require(now >= unlockDate, "Funds cannot be withdrawn yet");
       ERC20 token = ERC20(_tokenContract);
       uint256 tokenBalance = token.balanceOf(this);
       token.transfer(owner, tokenBalance);
       emit WithdrewTokens(_tokenContract, msg.sender, tokenBalance);
    }

    // callable by owner only, after specified time, only for Tokens implementing ERC20
    function withdrawERC20Amount(address _tokenContract, uint256 _amount) onlyOwner public {
       require(now >= unlockDate, "Funds cannot be withdrawn yet");
       ERC20 token = ERC20(_tokenContract);
       uint256 tokenBalance = token.balanceOf(this);
       require(tokenBalance > _amount, "Not enough funds in the reserve");
       token.transfer(owner, _amount);
       emit WithdrewTokens(_tokenContract, msg.sender, _amount);
    }

    function info() public view returns(address, uint256, uint256) {
        return (owner, unlockDate, address(this).balance);
    }

    function calculateUnlockTime() public view returns (uint256, uint256) {
        uint256 time = now;
        uint256 UnlockTime = now + 90 days;
        return (time, UnlockTime);
    }
    
    function infoERC20(address _tokenContract) public view returns(address, uint256, uint256) {
        ERC20 token = ERC20(_tokenContract);
        return (owner, unlockDate, token.balanceOf(this));
    }
    
    function updateUnlockDate(uint256 _newDate) onlyOwner public {
        unlockDate = _newDate;
    }
    
    event Received(address from, uint256 amount);
    event Withdrew(address to, uint256 amount);
    event WithdrewTokens(address tokenContract, address to, uint256 amount);
}
