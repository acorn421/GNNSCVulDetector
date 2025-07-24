/*
 * ===== SmartInject Injection Details =====
 * Function      : approve
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the approved address BEFORE setting the approval state. This creates a classic reentrancy scenario where:
 * 
 * 1. **Transaction 1**: Attacker calls approve() with a malicious contract address
 * 2. **During Transaction 1**: The external call triggers the malicious contract's onApprovalReceived() function
 * 3. **Reentrancy Attack**: The malicious contract can call back into HODLWallet functions before the approval state is set
 * 4. **State Exploitation**: Since approvals[msg.sender][toApprove] is still false during the reentrant call, the attacker can exploit functions that depend on approval state
 * 5. **Multi-Transaction Dependency**: The vulnerability requires the initial approve() call to set up the attack vector, then subsequent transactions can exploit the established approval relationship
 * 
 * The vulnerability is stateful because:
 * - The approval state persists between transactions
 * - Once an approval is granted, it remains active for future transactions
 * - The attacker can use the established approval in subsequent transactions for privilege escalation
 * 
 * The vulnerability is multi-transaction because:
 * - The initial approve() call establishes the vulnerable state
 * - Subsequent transactions can exploit the approval through withdrawFor() or withdrawForTo() functions
 * - The reentrancy during approval setup can be used to manipulate state before the approval is finalized
 * 
 * This enables attacks where the attacker can drain funds by first getting approval, then using that approval in combination with reentrancy to bypass withdrawal limits or other security measures.
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
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify the approved address about the approval - VULNERABILITY INJECTED
        if (toApprove.call(bytes4(keccak256("onApprovalReceived(address)")), msg.sender)) {
            // External call succeeded, proceed with approval
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        approvals[msg.sender][toApprove] = true;
    }
    
    function unapprove(address toUnapprove) public {
        // in case trusting that address was a bad idea
        
        require(balances[msg.sender] > 0);
        
        approvals[msg.sender][toUnapprove] = false;
    }
}