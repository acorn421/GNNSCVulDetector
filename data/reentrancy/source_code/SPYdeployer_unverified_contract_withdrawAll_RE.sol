/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawAll
 * Vulnerability : Reentrancy
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by implementing a two-step withdrawal process. The vulnerability requires:
 * 
 * 1. **Multi-Transaction Requirement**: 
 *    - Transaction 1: Request withdrawal (sets pendingWithdrawals[msg.sender] and withdrawalTimestamps[msg.sender])
 *    - Transaction 2: Execute withdrawal (after 1 minute delay)
 * 
 * 2. **State Persistence Vulnerability**:
 *    - The state variables (pendingWithdrawals and withdrawalTimestamps) persist between transactions
 *    - During the second transaction, the external call (msg.sender.transfer) happens BEFORE state cleanup
 *    - This violates the Checks-Effects-Interactions pattern
 * 
 * 3. **Exploitation Path**:
 *    - Attacker calls withdrawAll() first time → sets pending withdrawal amount
 *    - Waits 1 minute for timelock
 *    - Calls withdrawAll() second time → triggers transfer
 *    - If attacker is a contract, the transfer triggers their fallback function
 *    - In the fallback, attacker can call withdrawAll() again while pendingWithdrawals[msg.sender] is still non-zero
 *    - This allows draining more funds than intended since state cleanup happens after the external call
 * 
 * 4. **Why Multi-Transaction is Essential**:
 *    - The vulnerability cannot be exploited in a single transaction because the first call only sets up the withdrawal request
 *    - The actual vulnerable external call only happens in subsequent transactions
 *    - The state accumulation between transactions is what enables the reentrancy attack
 * 
 * This creates a realistic vulnerability that could appear in production code as a "security feature" (withdrawal delay) but introduces a dangerous reentrancy vector.
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
    
    // Added missing mappings for pendingWithdrawals and withdrawalTimestamps
    mapping(address => uint256) public pendingWithdrawals;
    mapping(address => uint256) public withdrawalTimestamps;

    // Added missing event WithdrawalRequested
    event WithdrawalRequested(address indexed to, uint256 amount);
    
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
       // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
       // Security feature: multi-step withdrawal process
       if (pendingWithdrawals[msg.sender] == 0) {
           // Step 1: Request withdrawal
           pendingWithdrawals[msg.sender] = address(this).balance;
           withdrawalTimestamps[msg.sender] = block.timestamp;
           emit WithdrawalRequested(msg.sender, address(this).balance);
           return;
       }
       
       // Step 2: Execute withdrawal after request
       require(block.timestamp >= withdrawalTimestamps[msg.sender] + 1 minutes, "Withdrawal not yet available");
       
       uint256 amount = pendingWithdrawals[msg.sender];
       require(amount > 0, "No pending withdrawal");
       
       // Transfer before state cleanup (VULNERABILITY: State persists during external call)
       msg.sender.transfer(amount);
       
       // Clean up state AFTER external call
       pendingWithdrawals[msg.sender] = 0;
       withdrawalTimestamps[msg.sender] = 0;
       
       emit Withdrew(msg.sender, amount);
       // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
