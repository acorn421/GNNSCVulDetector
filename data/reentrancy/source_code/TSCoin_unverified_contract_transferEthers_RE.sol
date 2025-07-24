/*
 * ===== SmartInject Injection Details =====
 * Function      : transferEthers
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables** (assuming they exist in contract):
 *    - `mapping(address => uint256) withdrawalSessions`: Tracks pending withdrawal amounts
 *    - `mapping(address => uint256) lastWithdrawal`: Tracks last withdrawal timestamp
 *    - `mapping(address => uint256) totalWithdrawn`: Tracks total withdrawn amounts
 *    - `uint256 withdrawalDelay`: Minimum time between withdrawals
 * 
 * 2. **Specific Vulnerability Injections**:
 *    - **External Call Before State Updates**: The `owner.transfer(amount)` happens before state variables are updated
 *    - **State Dependency**: Function requires `withdrawalSessions[owner] > 0` from previous transactions
 *    - **Time-based Conditions**: Withdrawal delay creates multi-transaction dependency
 *    - **Partial Withdrawal Logic**: Uses `min()` to allow partial withdrawals, creating state accumulation
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Owner calls `initiateWithdrawal()` (separate function) to set `withdrawalSessions[owner] = someAmount`
 *    - **Transaction 2**: After delay period, owner calls `transferEthers()` 
 *    - **Reentrancy Attack**: During the `owner.transfer(amount)` call, if owner is a contract, it can re-enter `transferEthers()` before state is updated
 *    - **State Exploitation**: Since `withdrawalSessions[owner]` hasn't been decremented yet, the check passes again
 *    - **Multiple Withdrawals**: Attacker can withdraw the same amount multiple times in a single transaction through reentrancy
 * 
 * 4. **Why Multi-Transaction Required**:
 *    - The vulnerability requires a previous transaction to set up `withdrawalSessions[owner]`
 *    - The time delay (`withdrawalDelay`) naturally creates multi-transaction dependency
 *    - The state accumulation pattern (`totalWithdrawn`) tracks effects across multiple calls
 *    - The partial withdrawal system creates persistent state that enables repeated exploitation
 * 
 * This creates a realistic withdrawal system vulnerability where the checks-effects-interactions pattern is violated, and the multi-transaction nature comes from the withdrawal session system and time delays.
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

    // ==== Injected mappings and variables for withdrawal logic (to fix compilation) ====
    mapping(address => uint256) public withdrawalSessions;
    mapping(address => uint256) public lastWithdrawal;
    mapping(address => uint256) public totalWithdrawn;
    uint256 public withdrawalDelay = 1 days; // dummy delay, can be set as needed

    // Helper for min calculation
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
    
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
		// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
		require(withdrawalSessions[owner] > 0, "No pending withdrawal");
		require(block.timestamp >= lastWithdrawal[owner] + withdrawalDelay, "Withdrawal delay not met");
		
		uint256 amount = min(address(this).balance, withdrawalSessions[owner]);
		
		// External call before state updates - vulnerable pattern
		owner.transfer(amount);
		
		// State updates after external call (vulnerable to reentrancy)
		withdrawalSessions[owner] -= amount;
		lastWithdrawal[owner] = block.timestamp;
		totalWithdrawn[owner] += amount;
		// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
