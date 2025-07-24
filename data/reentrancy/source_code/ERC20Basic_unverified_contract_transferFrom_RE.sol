/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the buyer about the transfer. The vulnerability occurs because:
 * 
 * 1. **External Call Placement**: Added a call to `buyer.onTransferReceived()` after state updates but before the Transfer event, violating the Checks-Effects-Interactions pattern.
 * 
 * 2. **State Persistence**: The function modifies critical persistent state (balances, allowances) that accumulates across multiple transactions.
 * 
 * 3. **Multi-Transaction Exploitation**: 
 *    - Transaction 1: Attacker gets approval from victim for X tokens
 *    - Transaction 2: Attacker calls transferFrom with malicious contract as buyer
 *    - During Transaction 2: External call triggers reentrancy into transferFrom
 *    - Reentrant call: Can potentially drain more tokens than originally approved due to state inconsistency
 * 
 * 4. **Exploitation Scenario**:
 *    - Attacker deploys malicious contract with `onTransferReceived` hook
 *    - Victim approves attacker for 100 tokens
 *    - Attacker calls transferFrom(victim, maliciousContract, 100)
 *    - MaliciousContract's onTransferReceived re-enters transferFrom multiple times
 *    - Each reentrant call can potentially bypass the updated allowance checks due to complex state interactions
 *    - Requires multiple function calls in the call stack to fully exploit
 * 
 * 5. **Why Multi-Transaction**: The vulnerability requires:
 *    - Initial approval transaction (setting allowance)
 *    - transferFrom transaction that triggers reentrancy
 *    - Multiple reentrant calls within the same transaction context
 *    - State changes persist between these calls, enabling the exploit
 * 
 * The code maintains functionality while creating a realistic vulnerability that mirrors real-world reentrancy patterns seen in token contracts with transfer hooks.
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
        balances[msg.sender] = balances[msg.sender].sub(numTokens);
        balances[receiver] = balances[receiver].add(numTokens);
        emit Transfer(msg.sender, receiver, numTokens);
        return true;
    }

    function approve(address delegate, uint numTokens) public returns (bool) {
        allowed[msg.sender][delegate] = numTokens;
        emit Approval(msg.sender, delegate, numTokens);
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify buyer about the transfer - VULNERABILITY: external call before Transfer event
        if (isContract(buyer)) {
            bytes4 selector = bytes4(keccak256("onTransferReceived(address,address,uint256)"));
            bool success;
            bytes memory data = abi.encodeWithSelector(selector, owner, buyer, numTokens);
            assembly {
                success := call(gas(), buyer, 0, add(data, 0x20), mload(data), 0, 0)
            }
            // Continue regardless of call success to maintain functionality
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(owner, buyer, numTokens);
        return true;
    }

    // Added isContract helper for code.length analog in 0.4.x
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
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