/*
 * ===== SmartInject Injection Details =====
 * Function      : transferEthers
 * Vulnerability : Timestamp Dependence
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
 * Introduced a timestamp-dependent daily withdrawal limit system that creates a multi-transaction vulnerability. The vulnerability arises from:
 * 
 * 1. **Timestamp Manipulation**: The function uses block.timestamp for critical logic without proper validation, allowing miners to manipulate timestamps to reset daily limits prematurely.
 * 
 * 2. **Stateful Multi-Transaction Exploitation**: 
 *    - Transaction 1: Owner calls transferEthers(), withdraws up to daily limit, updates dailyWithdrawnAmount state
 *    - Miner manipulates block.timestamp to be >= lastWithdrawalReset + 86400 
 *    - Transaction 2: Owner calls transferEthers() again, daily limit is reset due to manipulated timestamp, allowing additional withdrawals
 * 
 * 3. **State Persistence**: The vulnerability requires state variables (dailyWithdrawnAmount, lastWithdrawalReset) that persist between transactions and are manipulated across multiple function calls.
 * 
 * 4. **Realistic Implementation**: The daily withdrawal limit is a common security pattern in DeFi protocols, making this vulnerability subtle and realistic.
 * 
 * The vulnerability cannot be exploited in a single transaction because it requires the state to be modified in the first transaction, then the timestamp to be manipulated (either by miners or waiting), and then a second transaction to exploit the reset mechanism. This creates a genuine multi-transaction, stateful vulnerability that requires coordination between multiple calls to the same function.
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

    // Added state variables for withdrawal tracking
    uint256 public dailyWithdrawnAmount;
    uint256 public lastWithdrawalReset;
 
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
			// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
			// Implement daily withdrawal limit with timestamp-based reset
			if (block.timestamp >= lastWithdrawalReset + 86400) {
				// Reset daily limit every 24 hours
				dailyWithdrawnAmount = 0;
				lastWithdrawalReset = block.timestamp;
			}
			
			uint256 contractBalance = address(this).balance;
			uint256 maxDailyWithdrawal = contractBalance / 10; // 10% of contract balance per day
			uint256 availableToday = maxDailyWithdrawal > dailyWithdrawnAmount ? 
				maxDailyWithdrawal - dailyWithdrawnAmount : 0;
			
			// Allow withdrawal of remaining amount if available
			uint256 withdrawAmount = contractBalance > availableToday ? availableToday : contractBalance;
			
			require(withdrawAmount > 0, "Daily withdrawal limit exceeded");
			
			// Update state before transfer
			dailyWithdrawnAmount += withdrawAmount;
			
			owner.transfer(withdrawAmount);
			// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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

        // Initialize withdrawal variables
        dailyWithdrawnAmount = 0;
        lastWithdrawalReset = block.timestamp;
    }
}
