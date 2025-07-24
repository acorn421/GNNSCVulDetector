/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to receiver contracts before state updates. This creates a classic CEI (Checks-Effects-Interactions) pattern violation where:
 * 
 * 1. **External Call Added**: The function now calls `receiver.call()` to notify contract receivers of incoming transfers via an `onTokenReceived` callback
 * 2. **State Update Moved**: Balance updates happen AFTER the external call, allowing reentrancy during the callback
 * 3. **Multi-Transaction Requirement**: The vulnerability requires multiple transactions because:
 *    - Transaction 1: Attacker deploys malicious receiver contract
 *    - Transaction 2: Victim calls transfer() to malicious contract, triggering callback
 *    - Transaction 3+: During callback, malicious contract can call transfer() again before balances are updated
 * 4. **Stateful Nature**: The vulnerability depends on persistent balance state that accumulates across transactions, allowing the attacker to drain more funds than they should have access to
 * 
 * The exploit works by having the malicious receiver contract call back into transfer() during the callback, before the sender's balance is decreased, potentially allowing multiple withdrawals from the same initial balance.
 */
pragma solidity ^0.4.19;

contract ERC20Basic {

    string public constant name = "Computer Parts Investments";
    string public constant symbol = "CPI";
    uint8 public constant decimals = 18;  

    event Approval(address indexed tokenOwner, address indexed spender, uint tokens);
    event Transfer(address indexed from, address indexed to, uint tokens);

    mapping(address => uint256) balances;

    mapping(address => mapping (address => uint256)) allowed;
    
    uint256 totalSupply_;

    using SafeMath for uint256;

   constructor(uint256 total) public {  
	totalSupply_ = total;
	balances[msg.sender] = totalSupply_;
    }  

    function totalSupply() public view returns (uint256) {
	return totalSupply_;
    }
    
    function balanceOf(address tokenOwner) public view returns (uint) {
        return balances[tokenOwner];
    }

    function transfer(address receiver, uint numTokens) public returns (bool) {
        require(numTokens <= balances[msg.sender]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call before state update - creates reentrancy vulnerability
        // Check if receiver is a contract and notify them of incoming transfer
        if (isContract(receiver)) {
            // Call receiver's callback function - vulnerable to reentrancy
            receiver.call(bytes4(keccak256("onTokenReceived(address,uint256,bytes)")), msg.sender, numTokens, "");
            // Continue execution regardless of callback success
        }
        
        // State updates occur AFTER external call - violation of CEI pattern
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] = balances[msg.sender].sub(numTokens);
        balances[receiver] = balances[receiver].add(numTokens);
        emit Transfer(msg.sender, receiver, numTokens);
        return true;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }

    function approve(address delegate, uint numTokens) public returns (bool) {
        allowed[msg.sender][delegate] = numTokens;
        Approval(msg.sender, delegate, numTokens);
        return true;
    }

    function allowance(address owner, address delegate) public view returns (uint) {
        return allowed[owner][delegate];
    }

    function transferFrom(address owner, address buyer, uint numTokens) public returns (bool) {
        require(numTokens <= balances[owner]);    
        require(numTokens <= allowed[owner][msg.sender]);
    
        balances[owner] = balances[owner].sub(numTokens);
        allowed[owner][msg.sender] = allowed[owner][msg.sender].sub(numTokens);
        balances[buyer] = balances[buyer].add(numTokens);
        Transfer(owner, buyer, numTokens);
        return true;
    }
}

library SafeMath { 
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
      assert(b <= a);
      return a - b;
    }
    
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
      uint256 c = a + b;
      assert(c >= a);
      return c;
    }
}