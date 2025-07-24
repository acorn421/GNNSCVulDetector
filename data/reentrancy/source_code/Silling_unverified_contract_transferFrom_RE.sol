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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the buyer contract before state updates. The vulnerability violates the checks-effects-interactions pattern by placing an external call after validation checks but before critical state modifications. This creates a time window where the contract state is inconsistent, enabling multi-transaction exploitation.
 * 
 * **Specific Changes Made:**
 * 1. Added external call to buyer contract using low-level call() function
 * 2. Positioned the external call after require() checks but before state updates
 * 3. Added code length check to only call contracts (buyer.code.length > 0)
 * 4. Implemented realistic "transfer notification" functionality that might appear in production
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls transferFrom() with malicious buyer contract
 * 2. **During TX1**: External call triggers malicious buyer's onTokenReceived() function
 * 3. **Reentrancy**: Malicious contract calls transferFrom() again before first call completes
 * 4. **Exploitation**: Second call sees unchanged balances/allowances, enables double-spending
 * 5. **Transaction 2+**: Attacker can repeat the pattern to drain funds across multiple transactions
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the attacker to control a contract that receives the callback
 * - State changes persist between transactions, creating accumulated damage
 * - Each successful reentrancy call can be followed by additional exploitation transactions
 * - The allowance mechanism requires multiple calls to fully exploit larger amounts
 * - Complex attack scenarios require setup transactions to position allowances and balances optimally
 * 
 * The vulnerability is realistic because token transfer notifications are common in DeFi protocols, making this type of integration believable in production code.
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
    
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // VULNERABILITY: External call before state updates - enables reentrancy
        if (isContract(buyer)) {
            // Notify buyer contract about incoming transfer
            (bool success, ) = buyer.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", owner, numTokens));
            require(success, "Transfer notification failed");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[owner] = balances[owner].sub(numTokens);
        allowed[owner][msg.sender] = allowed[owner][msg.sender].sub(numTokens);
        balances[buyer] = balances[buyer].add(numTokens);
        emit Transfer(owner, buyer, numTokens);
        return true;
    }
    
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
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
