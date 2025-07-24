/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY**
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call**: Introduced a call to `_to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value))` after balance updates but before allowance decrement
 * 2. **Violates Checks-Effects-Interactions**: The external call occurs before the critical state update (allowance decrement), creating a reentrancy window
 * 3. **Added Contract Detection**: Uses `_to.code.length > 0` to detect if recipient is a contract and trigger the notification
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Victim approves attacker contract for 1000 tokens via `approve(attackerContract, 1000)`
 * 2. **Transaction 2**: Attacker calls `transferFrom(victim, attackerContract, 500)` which:
 *    - Updates balances (victim -500, attacker +500)
 *    - Calls `attackerContract.onTokenReceived()` - **REENTRANCY POINT**
 *    - In the reentrant call, attacker calls `transferFrom(victim, attackerContract, 500)` again
 *    - The allowance is still 1000 (not yet decremented), so the second transfer succeeds
 *    - Attacker receives 1000 tokens total using only 1000 allowance (should be 500 each)
 * 
 * **Why Multi-Transaction is Required:**
 * - **State Dependency**: The vulnerability depends on the allowance state set in a previous transaction (approval)
 * - **Persistent State**: The allowance remains in storage between transactions, enabling the attack
 * - **Sequential Exploitation**: Requires approval first, then the vulnerable transferFrom call - cannot be done atomically
 * - **Reentrant State Manipulation**: The attacker's contract must be deployed and have the reentrant logic, requiring separate setup
 * 
 * **Real-World Impact:**
 * - Attacker can drain more tokens than approved
 * - The allowance mechanism becomes ineffective as the same allowance can be used multiple times
 * - Requires coordination between multiple transactions making it a stateful vulnerability
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
    
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    
    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
    
	function () public payable {
        createTokens();
    } 
    
    function BCE() public { // Fixed constructor name to match contract
        owner = msg.sender;
    }
    
	function createTokens() public payable {
	    require(_totalSupply <= 21000000); // Max Bitcoin Ethers in circulation = 21 mil. 
        require(msg.value > 0);
        uint256 tokens = msg.value.mul(RATE);
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
        emit Transfer(msg.sender, _to, _value);
        return true;
    }
    
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success){
		require(_to != 0x0);
        require(allowed [_from][msg.sender] >= 0 && balances[_from] >= _value && _value > 0);
        balances[_from] = balances[_from].sub(_value);
        balances[_to] = balances[_to].add(_value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract about the transfer - VULNERABILITY: External call before allowance update
        if (isContract(_to)) {
            bool notificationSuccess = _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
            require(notificationSuccess);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        emit Transfer(_from, _to, _value);
        return true;
    }
    
    function approve(address _spender, uint256 _value) public returns (bool success){
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function allowance(address _owner, address _spender) public constant returns (uint256 remaining){
        return allowed[_owner][_spender];
    }

    // Helper for contract check (since address.code is not available in 0.4.x)
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}

