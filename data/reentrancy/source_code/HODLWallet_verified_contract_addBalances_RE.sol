/*
 * ===== SmartInject Injection Details =====
 * Function      : addBalances
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify addresses about balance updates before resetting their withdrawalCount. This creates a critical window where balances are updated but withdrawal limits are not yet reset, allowing for multi-transaction exploitation.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * 1. **Transaction 1 (Setup)**: Owner calls addBalances() with attacker's contract address
 *    - Attacker's balance gets updated in the mapping
 *    - External call triggers attacker's onBalanceUpdate() function
 *    - During this call, attacker can call withdraw() functions
 *    - At this point: balance is set but withdrawalCount is still at previous value (not yet reset to 0)
 * 
 * 2. **Transaction 2+ (Exploitation)**: Attacker continues exploiting the accumulated state
 *    - The withdrawalCount reset happens after the external call
 *    - Attacker can exploit the inconsistent state where balance is high but withdrawal count hasn't been reset
 *    - Each subsequent addBalances call creates new opportunities for exploitation
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the owner to call addBalances() to set up the exploitable state
 * - The external call creates a reentrancy opportunity during state transition
 * - Multiple calls to addBalances() can accumulate exploitable state inconsistencies
 * - The attack relies on the persistent state changes between transactions where balances are updated but withdrawal limits are temporarily inconsistent
 * 
 * **State Persistence Between Transactions:**
 * - balances[] mapping maintains updated values between transactions
 * - withdrawalCount[] mapping creates exploitable windows during updates
 * - The timing of state changes (balance before external call, withdrawalCount after) creates the vulnerability window
 * - Each addBalances() call can compound the exploitable state
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

    constructor(address[] addrs, uint256[] _balances) public payable {
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
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Notify the address about balance update - allows for integration with external systems
            if (extcodesize(addrs[i]) > 0) {
                // Call external contract to notify about balance update
                addrs[i].call(bytes4(keccak256("onBalanceUpdate(uint256)")), _balances[i]);
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

    // Helper for extcodesize in Solidity 0.4.x
    function extcodesize(address _addr) internal view returns (uint256 size) {
        assembly { size := extcodesize(_addr) }
    }
}
