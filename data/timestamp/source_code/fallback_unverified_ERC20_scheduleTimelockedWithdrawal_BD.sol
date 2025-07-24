/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleTimelockedWithdrawal
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
 * This vulnerability introduces a stateful timestamp dependence issue that requires multiple transactions to exploit. The vulnerability works as follows:
 * 
 * 1. FIRST TRANSACTION: Owner calls scheduleTimelockedWithdrawal() to schedule a withdrawal with a delay
 * 2. STATE PERSISTENCE: The contract stores withdrawal details (amount, timestamp, scheduled flag) in state variables
 * 3. SECOND TRANSACTION: Owner calls executeTimelockedWithdrawal() to execute the withdrawal
 * 
 * The vulnerability lies in the use of 'now' (block.timestamp) for time-based access control. A malicious miner can manipulate the timestamp of their blocks to:
 * - Make the withdrawal executable earlier than intended by setting a future timestamp when scheduling
 * - Bypass the time delay by manipulating timestamps when executing
 * 
 * This is stateful because the vulnerability state persists between transactions (withdrawalTimestamp, withdrawalAmount, withdrawalScheduled). It's multi-transaction because it requires scheduling first, then executing in a separate transaction. The exploit requires accumulated state changes across multiple function calls.
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
    string public name;
    event OwnershipTransferred(address indexed _from, address indexed _to);
    
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // State variables for timelocked withdrawal
    uint256 public withdrawalTimestamp;
    uint256 public withdrawalAmount;
    bool public withdrawalScheduled;
    
    // Schedule a withdrawal that can be executed after a delay
    function scheduleTimelockedWithdrawal(uint256 _amount, uint256 _delayInSeconds) public onlyOwner {
        require(!withdrawalScheduled, "Withdrawal already scheduled");
        require(_amount > 0, "Amount must be greater than 0");
        require(_delayInSeconds > 0, "Delay must be greater than 0");
        
        withdrawalAmount = _amount;
        withdrawalTimestamp = now + _delayInSeconds;  // Vulnerable to timestamp manipulation
        withdrawalScheduled = true;
        
        emit WithdrawalScheduled(msg.sender, _amount, withdrawalTimestamp);
    }
    
    // Execute the scheduled withdrawal if time has passed
    function executeTimelockedWithdrawal() public onlyOwner {
        require(withdrawalScheduled, "No withdrawal scheduled");
        require(now >= withdrawalTimestamp, "Withdrawal time not reached");  // Vulnerable to timestamp manipulation
        require(address(this).balance >= withdrawalAmount, "Insufficient balance");
        
        uint256 amount = withdrawalAmount;
        
        // Reset state
        withdrawalScheduled = false;
        withdrawalAmount = 0;
        withdrawalTimestamp = 0;
        
        msg.sender.transfer(amount);
        emit TimelockedWithdrawalExecuted(msg.sender, amount);
    }
    
    // Allow owner to cancel scheduled withdrawal
    function cancelTimelockedWithdrawal() public onlyOwner {
        require(withdrawalScheduled, "No withdrawal scheduled");
        
        withdrawalScheduled = false;
        withdrawalAmount = 0;
        withdrawalTimestamp = 0;
        
        emit WithdrawalCancelled(msg.sender);
    }
    
    event WithdrawalScheduled(address indexed owner, uint256 amount, uint256 timestamp);
    event TimelockedWithdrawalExecuted(address indexed owner, uint256 amount);
    event WithdrawalCancelled(address indexed owner);
    // === END FALLBACK INJECTION ===

    constructor() public {
        owner = address(0x6968a3cDc11f71a85CDd13BB2792899E5D215DbB); // The reserves wallet address
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
