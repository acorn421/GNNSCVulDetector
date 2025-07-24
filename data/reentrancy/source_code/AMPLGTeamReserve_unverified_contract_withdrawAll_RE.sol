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
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables** (assumes these exist in contract):
 *    - `mapping(address => uint256) public pendingWithdrawals` - tracks pending withdrawal amounts
 *    - `uint256 public totalPendingWithdrawals` - tracks total pending withdrawals
 * 
 * 2. **Created Vulnerable State Management**:
 *    - Stage 1: Sets pending withdrawal state BEFORE external call
 *    - Stage 2: External call (transfer) that can trigger reentrancy
 *    - Stage 3: State cleanup AFTER external call (creates vulnerable window)
 * 
 * 3. **Multi-Transaction Exploitation Pattern**:
 *    - **Transaction 1**: Legitimate withdrawal call sets pendingWithdrawals[owner] = balance
 *    - **Transaction 2**: During the transfer callback, attacker can exploit inconsistent state
 *    - The vulnerability exists because state is updated after the external call, violating CEI pattern
 * 
 * 4. **Stateful Nature**:
 *    - The vulnerability relies on persistent state (pendingWithdrawals mapping)
 *    - State changes accumulate between transactions
 *    - Multiple function calls can exploit the inconsistent state window
 * 
 * 5. **Realistic Vulnerability**: 
 *    - Based on real-world patterns of staged withdrawal systems
 *    - Common in contracts that implement withdrawal limits or approval mechanisms
 *    - The state tracking appears legitimate but creates a reentrancy window
 * 
 * **Multi-Transaction Exploitation**:
 * - Transaction 1: Call withdrawAll() → sets pendingWithdrawals but triggers reentrancy
 * - Transaction 2: In callback, exploit inconsistent state (pending withdrawal marked but not cleared)
 * - Transaction 3+: Additional calls can compound the vulnerability through accumulated state manipulation
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
    mapping(address => uint256) public pendingWithdrawals;
    uint256 public totalPendingWithdrawals;

    modifier onlyOwner {
        require(msg.sender == owner, "You are not the owner");
        _;
    }

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
       // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
       require(pendingWithdrawals[msg.sender] == 0, "Pending withdrawal already exists");
       
       uint256 amount = address(this).balance;
       require(amount > 0, "No funds to withdraw");
       
       // Stage 1: Mark withdrawal as pending (stateful)
       pendingWithdrawals[msg.sender] = amount;
       totalPendingWithdrawals += amount;
       
       // Stage 2: External call before state cleanup (reentrancy point)
       msg.sender.transfer(amount);
       
       // Stage 3: State cleanup after external call (vulnerable window)
       pendingWithdrawals[msg.sender] = 0;
       totalPendingWithdrawals -= amount;
       
       emit Withdrew(msg.sender, amount);
       // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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