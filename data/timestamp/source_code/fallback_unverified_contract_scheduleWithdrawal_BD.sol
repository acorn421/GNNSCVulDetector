/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleWithdrawal
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue where the contract relies on 'now' (block.timestamp) for time-based access control. The vulnerability is stateful and multi-transaction because: 1) First, the owner must call scheduleWithdrawal() to set up a scheduled withdrawal with a timestamp, 2) Then, they must wait for the delay period and call executeScheduledWithdrawal() in a separate transaction. A malicious miner could manipulate block timestamps to either prevent legitimate withdrawals or allow early execution of scheduled withdrawals, compromising the intended time-based security mechanism.
 */
pragma solidity ^0.4.24;

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

contract SPYdeployer {

    address public owner;
    string public  name;
    event OwnershipTransferred(address indexed _from, address indexed _to);
    
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // State variables for timed withdrawal functionality
    mapping(address => uint256) scheduledWithdrawals;
    mapping(address => uint256) withdrawalTimestamps;
    uint256 public withdrawalDelay = 24 hours; // Default 24 hour delay
    
    constructor() public {
        owner = address(0x6968a3cDc11f71a85CDd13BB2792899E5D215DbB); // The reserves wallet address
    }

    // Schedule a withdrawal with timestamp-based delay
    function scheduleWithdrawal(uint256 _amount) public onlyOwner {
        require(_amount > 0, "Amount must be greater than 0");
        require(address(this).balance >= _amount, "Insufficient balance");
        // Store scheduled withdrawal and timestamp
        scheduledWithdrawals[msg.sender] = _amount;
        withdrawalTimestamps[msg.sender] = now + withdrawalDelay;
        emit WithdrawalScheduled(msg.sender, _amount, withdrawalTimestamps[msg.sender]);
    }
    
    // Execute scheduled withdrawal after delay period
    function executeScheduledWithdrawal() public onlyOwner {
        require(scheduledWithdrawals[msg.sender] > 0, "No scheduled withdrawal");
        require(now >= withdrawalTimestamps[msg.sender], "Withdrawal not yet available");
        uint256 amount = scheduledWithdrawals[msg.sender];
        // Clear the scheduled withdrawal
        scheduledWithdrawals[msg.sender] = 0;
        withdrawalTimestamps[msg.sender] = 0;
        // Transfer funds
        msg.sender.transfer(amount);
        emit ScheduledWithdrawalExecuted(msg.sender, amount);
    }
    
    // Update withdrawal delay (only owner can modify timing rules)
    function updateWithdrawalDelay(uint256 _newDelay) public onlyOwner {
        require(_newDelay >= 1 hours, "Delay must be at least 1 hour");
        withdrawalDelay = _newDelay;
        emit WithdrawalDelayUpdated(_newDelay);
    }
    
    event WithdrawalScheduled(address indexed owner, uint256 amount, uint256 executeTime);
    event ScheduledWithdrawalExecuted(address indexed owner, uint256 amount);
    event WithdrawalDelayUpdated(uint256 newDelay);
    // === END FALLBACK INJECTION ===

    modifier onlyOwner {
        require(msg.sender == owner, "You are not the owner");
        _;
    }

    // transfer Ownership to other address
    function transferOwnership(address _newOwner) public onlyOwner {
        require(_newOwner != address(0x0));
        emit OwnershipTransferred(owner,_newOwner);
        owner = _newOwner;
    }
    

    // keep all tokens sent to this address
    function() public payable {
        emit Received(msg.sender, msg.value);
    }

    // callable by owner only, after specified time
    function withdrawAll() onlyOwner public {
       // withdraw balance
       msg.sender.transfer(address(this).balance);
       emit Withdrew(msg.sender, address(this).balance);
    }

    // callable by owner only, after specified time, only for Tokens implementing ERC20
    function withdrawERC20(address _tokenContract) onlyOwner public {
       ERC20 token = ERC20(_tokenContract);
       uint256 tokenBalance = token.balanceOf(this);
       token.transfer(owner, tokenBalance);
       emit WithdrewTokens(_tokenContract, msg.sender, tokenBalance);
    }

    // callable by owner only, after specified time, only for Tokens implementing ERC20
    function withdrawERC20Amount(address _tokenContract, uint256 _amount) onlyOwner public {
       ERC20 token = ERC20(_tokenContract);
       uint256 tokenBalance = token.balanceOf(this);
       require(tokenBalance >= _amount, "Not enough funds in the reserve");
       token.transfer(owner, _amount);
       emit WithdrewTokens(_tokenContract, msg.sender, _amount);
    }

    event Received(address from, uint256 amount);
    event Withdrew(address to, uint256 amount);
    event WithdrewTokens(address tokenContract, address to, uint256 amount);
}