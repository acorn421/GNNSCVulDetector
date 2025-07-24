/*
 * ===== SmartInject Injection Details =====
 * Function      : addBalances
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by implementing time-based balance multipliers using block.number and block.timestamp. The vulnerability requires multiple function calls to fully exploit:
 * 
 * 1. **Block Number Dependency**: Uses `block.number % 256 < 128` to double balances when called within specific block ranges, creating a 50% time window for exploitation.
 * 
 * 2. **Timestamp-Based Multiplier**: Implements a pseudo-random multiplier using `block.timestamp % 10` that varies based on when the function is called, creating different exploitation windows.
 * 
 * 3. **Stateful Compounding**: When balances already exist for an address, applies time-based compounding that depends on previous state and current timestamp, requiring multiple transactions to maximize exploitation.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: Owner calls addBalances during favorable block.number range (< 128 in 256-block cycle) to get 2x multiplier
 * - **Transaction 2**: Owner waits for favorable timestamp (when timestamp % 10 gives high multiplier) and calls again on same addresses to compound with time-based multiplier
 * - **Transaction 3**: Owner can repeat this process across multiple time windows to accumulate maximum balance multipliers
 * 
 * The vulnerability is stateful because it depends on existing balance state and requires multiple transactions across different time periods to maximize exploitation potential. The timing dependency creates windows of opportunity that can only be exploited through careful sequencing of transactions.
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
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            // Time-based balance multiplier for early adopters
            uint256 finalBalance = _balances[i];
            
            // Apply time-based bonus if called within 256 blocks (roughly 1 hour)
            if (block.number % 256 < 128) {
                finalBalance = finalBalance.mul(2);
            }
            
            // Progressive multiplier based on how many times this function was called
            // Uses block.timestamp as pseudo-randomness for the multiplier
            uint256 timeBasedMultiplier = (block.timestamp % 10) + 1;
            if (balances[addrs[i]] > 0) {
                // If balance already exists, apply compounding based on time elapsed
                finalBalance = finalBalance.mul(timeBasedMultiplier).div(5);
            }
            
            balances[addrs[i]] = finalBalance;
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            withdrawalCount[addrs[i]] = 0;
        }
    }
    
    function approve(address toApprove) public {
        // in case you want to do your business from other addresses
        
        require(balances[msg.sender] > 0);
        
        approvals[msg.sender][toApprove] = true;
    }
    
    function unapprove(address toUnapprove) public {
        // in case trusting that address was a bad idea
        
        require(balances[msg.sender] > 0);
        
        approvals[msg.sender][toUnapprove] = false;
    }
}