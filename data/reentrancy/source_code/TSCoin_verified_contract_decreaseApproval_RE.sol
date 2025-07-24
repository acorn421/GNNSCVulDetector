/*
 * ===== SmartInject Injection Details =====
 * Function      : decreaseApproval
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
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call Before State Update**: Introduced a callback mechanism that notifies the spender about approval changes via `_spender.call()` before updating the `allowed` mapping state.
 * 
 * 2. **Positioned Call in Reentrancy Window**: The external call occurs after reading the old approval value but before updating the state, creating a critical reentrancy vulnerability window.
 * 
 * 3. **Realistic Notification Feature**: The callback appears as a legitimate feature to notify spenders about approval changes, making the vulnerability subtle and realistic.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Setup Phase:**
 * - User calls `decreaseApproval(maliciousContract, 100)` 
 * - Current approval: 200 tokens
 * - External call triggers `maliciousContract.onApprovalChange()`
 * - During callback, malicious contract calls `transferFrom()` using the still-valid 200 token approval
 * - Original `decreaseApproval` completes, setting approval to 100
 * 
 * **Transaction 2 - Exploitation Phase:**
 * - User calls `decreaseApproval(maliciousContract, 50)` again
 * - Current approval: 100 tokens (from Transaction 1)
 * - External call triggers callback again
 * - Malicious contract calls `transferFrom()` using the current 100 token approval
 * - Original `decreaseApproval` completes, setting approval to 50
 * 
 * **Transaction 3 - Continued Exploitation:**
 * - Pattern repeats with accumulated stolen tokens from previous transactions
 * - Each transaction allows the malicious contract to extract more tokens than intended
 * - The vulnerability compounds across multiple transactions
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * 
 * 1. **State Accumulation**: The vulnerability becomes more profitable across multiple transactions as the malicious contract accumulates stolen tokens from each reentrancy opportunity.
 * 
 * 2. **Approval State Persistence**: The `allowed` mapping persists between transactions, allowing the attacker to exploit the approval amounts set in previous transactions.
 * 
 * 3. **Compound Effect**: Each transaction provides a new reentrancy window, and the cumulative effect of multiple exploitations results in significantly more token theft than a single transaction could achieve.
 * 
 * 4. **Cross-Function Interaction**: The vulnerability leverages the interaction between `decreaseApproval` and `transferFrom` functions, requiring multiple function calls across transactions to be fully exploited.
 * 
 * This creates a realistic, stateful vulnerability that requires multiple transactions to accumulate significant impact, making it an excellent example for security research and analysis.
 */
pragma solidity ^0.4.24;
 
contract TSCoin {
 
    uint256 totalSupply_; 
    string public constant name = "TSCoin";
    string public constant symbol = "TSC";
    uint8 public constant decimals = 18;
    uint256 public constant initialSupply = 200000000*(10**uint256(decimals));
	uint256 public buyPrice;
	address public owner;
 
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
 
    mapping (address => uint256) balances; 
    mapping (address => mapping (address => uint256)) allowed;
    
    function totalSupply() public view returns (uint256){
        return totalSupply_;
    }
 
    function balanceOf(address _owner) public view returns (uint256){
        return balances[_owner];
    }
 
    function allowance(address _owner, address _spender) public view returns (uint256) {
        return allowed[_owner][_spender];
  }


	
	function _transfer(address _from, address _to, uint256 _value) internal returns (bool ) {
        require(_to != address(0));
        require(balances[_from] >= _value); 
        balances[_from] = balances[_from] - _value; 
        balances[_to] = balances[_to] + _value; 
        emit Transfer(_from, _to, _value);
        return true;
    }
    
    function transfer(address _to, uint256 _value)  public {
        _transfer(msg.sender, _to, _value);
    }


		function _buy(address _from, uint256 _value) internal {
		uint256 _amount = (_value / buyPrice)*(10**uint256(decimals));
		_transfer(this, _from, _amount);
		emit Transfer(this, _from, _amount);
		}
		
		function() public payable{
			 _buy(msg.sender, msg.value);
		}
		
		function buy() public payable {
			_buy(msg.sender, msg.value);
		}
		
	

		function transferEthers() public {
			require(msg.sender == owner);
			owner.transfer(address(this).balance);
		}





 
    function approve(address _spender, uint256 _value) public returns (bool) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }
 
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
        require(_to != address(0));
        require(_value <= balances[_from]);
        require(_value <= allowed[_from][msg.sender]); 
        balances[_from] = balances[_from] - _value; 
        balances[_to] = balances[_to] + _value; 
        allowed[_from][msg.sender] = allowed[_from][msg.sender] - _value; 
        emit Transfer(_from, _to, _value); 
        return true; 
        } 
 
     function increaseApproval(address _spender, uint _addedValue) public returns (bool) { 
     allowed[msg.sender][_spender] = allowed[msg.sender][_spender] + _addedValue; 
     emit Approval(msg.sender, _spender, allowed[msg.sender][_spender]); 
     return true; 
     } 
 
    function decreaseApproval(address _spender, uint _subtractedValue) public returns (bool) { 
    uint oldValue = allowed[msg.sender][_spender]; 
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Notify spender about approval change before updating state
    // This creates a reentrancy window where state is inconsistent
    if (_spender.delegatecall.gas(2300)(bytes4(keccak256("onApprovalChange(address,uint256,uint256)")), msg.sender, oldValue, _subtractedValue)) {
        // Continue execution regardless of callback success
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    if (_subtractedValue > oldValue) {
        allowed[msg.sender][_spender] = 0;
    } 
        else {
        allowed[msg.sender][_spender] = oldValue - _subtractedValue;
    }
    emit Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
    return true;
    }
	

 
    constructor(uint256 prices) public {
        totalSupply_ = initialSupply;
        balances[this] = initialSupply;
        
		buyPrice = prices;
		owner = msg.sender;
    }
}
