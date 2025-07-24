/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the receiver contract after balance updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker deploys a malicious receiver contract that implements onTokenReceived()
 * 2. **Transaction 2**: Attacker calls transfer() to the malicious contract, which during the onTokenReceived() callback:
 *    - Records the current state (balances, msg.sender, etc.)
 *    - Does NOT reenter immediately but stores information for later exploitation
 * 3. **Transaction 3+**: Based on accumulated state information from previous callbacks, the malicious contract can:
 *    - Call transfer() again with carefully calculated amounts
 *    - Exploit the fact that balances were already updated but the transfer flow continues
 *    - Potentially manipulate other contract functions that depend on balance state
 * 
 * **Why Multi-Transaction:**
 * - The vulnerability accumulates information across multiple transfer calls
 * - Each callback builds up state about transfer patterns and balances
 * - The exploit becomes effective only after the attacker has gathered sufficient state information
 * - The timing of external calls creates windows for state manipulation that compound over multiple transactions
 * 
 * **State Persistence:**
 * - The malicious receiver contract maintains persistent state about received transfers
 * - Balance changes persist between transactions, enabling accumulated exploitation
 * - The external call happens after critical state changes but before function completion, creating a vulnerable window
 * 
 * This creates a realistic vulnerability where an attacker must perform multiple transactions to build up the necessary state and timing to successfully exploit the reentrancy condition.
 */
pragma solidity ^0.4.24;

contract Silling {

    string public constant name = "SILLING";
    string public constant symbol = "SLN";
    uint8 public constant decimals = 18;  


    event Approval(address indexed tokenOwner, address indexed spender, uint tokens);
    event Transfer(address indexed from, address indexed to, uint tokens);


    mapping(address => uint256) balances;

    mapping(address => mapping (address => uint256)) allowed;
    
    uint256 totalSupply_;

    using SafeMath for uint256;


   constructor() public {  
	totalSupply_ = 500000000 * 10 ** uint256(decimals);
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Vulnerability: External call after balance updates but before completion
        if (isContract(receiver)) {
            (bool success, ) = receiver.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, numTokens));
            // Continue execution regardless of call result
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(msg.sender, receiver, numTokens);
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    function isContract(address addr) internal view returns (bool) {
        uint size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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
        emit Transfer(owner, buyer, numTokens);
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