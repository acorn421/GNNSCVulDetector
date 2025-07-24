/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawERC20
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a timestamp-dependent daily withdrawal limit system that relies on block.timestamp for time calculations. The vulnerability requires state variables 'lastWithdrawalTime' and 'dailyWithdrawnAmount' to track withdrawal timing and amounts. This creates a multi-transaction vulnerability where miners can manipulate block.timestamp to bypass the daily limits by:
 * 
 * 1. Transaction 1: Make initial withdrawal to set lastWithdrawalTime
 * 2. Transaction 2+: Manipulate block.timestamp in subsequent blocks to reset the 24-hour cooldown period prematurely, allowing unlimited withdrawals
 * 
 * The vulnerability is stateful because it depends on persistent state variables that track withdrawal timing across transactions. It requires multiple transactions because the exploit depends on the sequence of setting initial timing state and then manipulating timestamps in future blocks to bypass the intended 24-hour restriction. A miner controlling block timestamps could effectively drain the contract by resetting the daily limit multiple times within an actual 24-hour period.
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
    
    // Variables for timestamp dependence vulnerability
    uint256 public lastWithdrawalTime;
    uint256 public dailyWithdrawnAmount;
    
    constructor() public {
        
        owner = address(0x6968a3cDc11f71a85CDd13BB2792899E5D215DbB); // The reserves wallet address
        lastWithdrawalTime = 0;
        dailyWithdrawnAmount = 0;
    }
    
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
    function() payable public {
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
       // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
       
       // Time-based withdrawal limit: 24 hours = 86400 seconds
       uint256 dailyLimit = tokenBalance / 10; // 10% of balance per day
       
       // Check if 24 hours have passed since last withdrawal
       if (block.timestamp >= lastWithdrawalTime + 86400) {
           // Reset daily withdrawal tracking
           lastWithdrawalTime = block.timestamp;
           dailyWithdrawnAmount = 0;
       }
       
       uint256 availableToWithdraw = dailyLimit - dailyWithdrawnAmount;
       uint256 withdrawAmount = tokenBalance > availableToWithdraw ? availableToWithdraw : tokenBalance;
       
       if (withdrawAmount > 0) {
           dailyWithdrawnAmount += withdrawAmount;
           token.transfer(owner, withdrawAmount);
           emit WithdrewTokens(_tokenContract, msg.sender, withdrawAmount);
       }
       // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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