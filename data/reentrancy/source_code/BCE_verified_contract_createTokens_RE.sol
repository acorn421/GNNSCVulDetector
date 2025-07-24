/*
 * ===== SmartInject Injection Details =====
 * Function      : createTokens
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
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Tracking**: Added `accumulatedPurchases` mapping to track user's total purchases across multiple transactions, and `bonusPaid` mapping to track bonus eligibility.
 * 
 * 2. **Multi-Transaction Requirement**: The vulnerability requires users to make multiple calls to `createTokens()` to accumulate at least 5 ether in purchases before the bonus becomes available.
 * 
 * 3. **Reentrancy Vector**: Added a bonus payout mechanism using `msg.sender.call.value()` that executes BEFORE critical state updates, creating a classic reentrancy vulnerability.
 * 
 * 4. **Exploitation Scenario**: 
 *    - Transaction 1-4: User calls `createTokens()` with 1.25 ether each time, accumulating 5 ether total
 *    - Transaction 5: User calls `createTokens()` again, triggering the bonus payout
 *    - During the `call.value()` execution, the attacker can re-enter `createTokens()` since `bonusPaid[msg.sender]` is set to true but the transaction hasn't completed
 *    - The re-entrant call will again trigger the bonus payout since the state changes haven't been committed
 *    - This allows draining the contract through multiple re-entrant calls within the same transaction
 * 
 * 5. **State Persistence**: The vulnerability relies on accumulated state (`accumulatedPurchases`) persisting across multiple transactions, making it impossible to exploit in a single transaction without prior setup.
 * 
 * The vulnerability is realistic as bonus/reward systems are common in token sales, and the accumulation requirement makes it stateful and multi-transaction dependent.
 */
pragma solidity ^0.4.18;

/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }  

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        // assert(b > 0); // Solidity automatically throws when dividing by 0
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold
        return c;
    }
  
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b <= a);
        return a - b;
    }
}

contract BCE {
    
    using SafeMath for uint256;
    
    uint public _totalSupply = 0; 
    
    string public constant symbol = "BCE";
    string public constant name = "Bitcoin Ether";
    uint8 public constant decimals = 18;
	uint256 public totalSupply = _totalSupply * 10 ** uint256(decimals);
    
    // 1 ether = 500 bitcoin ethers
    uint256 public constant RATE = 500; 
    
    address public owner;

    // Declaration of missing state variables
    mapping(address => uint256) public accumulatedPurchases;
    mapping(address => bool) public bonusPaid;
    
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    
    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
    
	function () public payable {
        createTokens();
    } 
    
    // Fix: Constructor should match contract name
    function BCE() public {
        owner = msg.sender;
    }
    
	function createTokens() public payable {
	    require(_totalSupply <= 21000000); // Max Bitcoin Ethers in circulation = 21 mil. 
        require(msg.value > 0);
        uint256 tokens = msg.value.mul(RATE);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add accumulated purchase tracking for bonus system
        accumulatedPurchases[msg.sender] = accumulatedPurchases[msg.sender].add(msg.value);
        
        // Check if user qualifies for bonus payout (requires accumulated purchases >= 5 ether)
        if (accumulatedPurchases[msg.sender] >= 5 ether && !bonusPaid[msg.sender]) {
            bonusPaid[msg.sender] = true;
            // External call before state updates - vulnerable to reentrancy
            msg.sender.call.value(accumulatedPurchases[msg.sender].div(10))(); // 10% bonus
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] = balances[msg.sender].add(tokens);
        _totalSupply = _totalSupply.add(tokens);
        owner.transfer(msg.value);
    } 
    
    function balanceOf(address _owner) public constant returns (uint256 balance){
        return balances[_owner];
    }
    
    function transfer(address _to, uint256 _value) internal returns (bool success) {
		require(_to != 0x0);
        require(balances[msg.sender] >= _value && _value > 0);
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        Transfer(msg.sender, _to, _value);
        return true;
    }
    
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success){
		require(_to != 0x0);
        require(allowed [_from][msg.sender] >= 0 && balances[_from] >= _value && _value > 0);
        balances[_from] = balances[_from].sub(_value);
        balances[_to] = balances[_to].add(_value);
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        Transfer(_from, _to, _value);
        return true;
    }
    
    function approve(address _spender, uint256 _value) public returns (bool success){
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function allowance(address _owner, address _spender) public constant returns (uint256 remaining){
        return allowed[_owner][_spender];
    }
}