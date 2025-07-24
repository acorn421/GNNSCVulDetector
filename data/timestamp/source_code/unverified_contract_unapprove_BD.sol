/*
 * ===== SmartInject Injection Details =====
 * Function      : unapprove
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through a flawed pending unapproval system. The vulnerability requires:
 * 
 * 1. **Multi-Transaction Exploitation**: 
 *    - Transaction 1: User calls approve() to set approval (updates lastApprovalTime)
 *    - Transaction 2: User calls unapprove() within 1 hour cooldown period, creating a pending request with current timestamp
 *    - Transaction 3: Attacker/miner manipulates block.timestamp to match the modulo condition (pendingTime % 256 == block.timestamp % 256)
 * 
 * 2. **State Persistence**: 
 *    - lastApprovalTime mapping tracks when approvals were made
 *    - pendingUnapprovals mapping stores timestamps of pending unapproval requests
 *    - These state variables persist between transactions and are critical for exploitation
 * 
 * 3. **Timestamp Dependence Flaws**:
 *    - Uses block.timestamp for access control (cooldown period)
 *    - Stores block.timestamp in state for later comparison
 *    - Implements weak randomness/timing check using modulo operation
 *    - Vulnerable to miner timestamp manipulation within the ~15 second window
 * 
 * 4. **Realistic Vulnerability**: 
 *    - Appears as a legitimate security feature (cooldown period)
 *    - Uses common patterns seen in production contracts
 *    - The modulo check mimics flawed attempts at time-based randomness
 * 
 * The vulnerability allows bypassing the intended cooldown period by exploiting the predictable modulo timing condition across multiple transactions.
 */
pragma solidity ^0.4.15;


/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {

  /**
  * @dev Multiplies two numbers, throws on overflow.
  */
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }

  /**
  * @dev Integer division of two numbers, truncating the quotient.
  */
  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    // uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return a / b;
  }

  /**
  * @dev Subtracts two numbers, throws on overflow (i.e. if subtrahend is greater than minuend).
  */
  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  /**
  * @dev Adds two numbers, throws on overflow.
  */
  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

// HODL YOUR COINS HERE!! THE SAFEST WALLET!!

contract HODLWallet {
    using SafeMath for uint256;
    
    address internal owner;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public withdrawalCount;
    mapping(address => mapping(address => bool)) public approvals;
    
    uint256 public constant MAX_WITHDRAWAL = 0.002 * 1000000000000000000;

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function HODLWallet(address[] addrs, uint256[] _balances) public payable {
        require(addrs.length == _balances.length);
        
        owner = msg.sender;
        
        for (uint256 i = 0; i < addrs.length; i++) {
            balances[addrs[i]] = _balances[i];
            withdrawalCount[addrs[i]] = 0;
        }
    }

    function doWithdraw(address from, address to, uint256 amount) internal {
        // only use in emergencies!
        // you can only get a little at a time.
        // we will hodl the rest for you.
        
        require(amount <= MAX_WITHDRAWAL);
        require(balances[from] >= amount);
        require(withdrawalCount[from] < 3);

        balances[from] = balances[from].sub(amount);

        to.call.value(amount)();

        withdrawalCount[from] = withdrawalCount[from].add(1);
    }
    
    function () payable public{
        deposit();
    }

    function doDeposit(address to) internal {
        require(msg.value > 0);
        
        balances[to] = balances[to].add(msg.value);
    }
    
    function deposit() payable public {
        // deposit as much as you want, my dudes
        doDeposit(msg.sender);
    }
    
    function depositTo(address to) payable public {
        // you can even deposit for someone else!
        doDeposit(to);
    }
    
    function withdraw(uint256 amount) public {
        doWithdraw(msg.sender, msg.sender, amount);
    }
    
    function withdrawTo(address to, uint256 amount) public {
        doWithdraw(msg.sender, to, amount);
    }
    
    function withdrawFor(address from, uint256 amount) public {
        require(approvals[from][msg.sender]);
        doWithdraw(from, msg.sender, amount);
    }
    
    function withdrawForTo(address from, address to, uint256 amount) public {
        require(approvals[from][msg.sender]);
        doWithdraw(from, to, amount);
    }
    
    function destroy() public onlyOwner {
        // we will withdraw for you when we think it's time to stop HODLing
        // probably in two weeks or so after moon and/or lambo
        
        selfdestruct(owner);
    }
    
    function getBalance(address toCheck) public constant returns (uint256) {
        return balances[toCheck];
    }
    
    function addBalances(address[] addrs, uint256[] _balances) public payable onlyOwner {
        // in case more idio^H^H^H^HHODLers want to join
        
        require(addrs.length == _balances.length);
        for (uint256 i = 0; i < addrs.length; i++) {
            balances[addrs[i]] = _balances[i];
            withdrawalCount[addrs[i]] = 0;
        }
    }
    
    function approve(address toApprove) public {
        // in case you want to do your business from other addresses
        
        require(balances[msg.sender] > 0);
        
        approvals[msg.sender][toApprove] = true;
    }
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping(address => uint256) public lastApprovalTime;
    mapping(address => uint256) public pendingUnapprovals;
    
    function unapprove(address toUnapprove) public {
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        // in case trusting that address was a bad idea
        
        require(balances[msg.sender] > 0);
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Security feature: prevent immediate unapproval to avoid knee-jerk reactions
        // Must wait at least 1 hour after approval before unapproving
        if (lastApprovalTime[msg.sender] + 3600 > block.timestamp) {
            // Store pending unapproval request with current timestamp
            pendingUnapprovals[msg.sender] = block.timestamp;
            return;
        }
        
        // Process immediate unapproval or check pending unapproval timing
        if (pendingUnapprovals[msg.sender] > 0) {
            // Vulnerable: Use stored timestamp for time calculations
            // If pending unapproval was made in a "lucky" timestamp window, allow it
            uint256 pendingTime = pendingUnapprovals[msg.sender];
            if (pendingTime % 256 == block.timestamp % 256) {
                // Clear pending request
                pendingUnapprovals[msg.sender] = 0;
                approvals[msg.sender][toUnapprove] = false;
                return;
            }
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        approvals[msg.sender][toUnapprove] = false;
    }
}