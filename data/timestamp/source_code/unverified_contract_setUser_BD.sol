/*
 * ===== SmartInject Injection Details =====
 * Function      : setUser
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability by adding time-based balance calculations that persist in user state. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added `user.registrationTime = block.timestamp` to store the initial registration timestamp in user state
 * 2. Implemented time-based bonus calculation that accumulates over time: `timeBonus = (block.timestamp - user.registrationTime) / 3600`
 * 3. Added early adopter bonus logic based on specific timestamp ranges
 * 4. These timestamp values are stored in state and used across multiple function calls
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1 (Setup)**: Attacker calls setUser to register and store initial timestamp
 * 2. **Time Manipulation**: Miner manipulates block.timestamp in subsequent blocks
 * 3. **Transaction 2+ (Exploitation)**: Attacker calls setUser again to trigger time-based bonuses with manipulated timestamps
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability requires the registration timestamp to be stored in state first
 * - The time-based bonus calculation depends on the difference between current block.timestamp and stored registrationTime
 * - An attacker cannot manipulate both the registration time AND the bonus calculation time in a single transaction
 * - The exploit requires time to pass (or timestamp manipulation) between the initial registration and bonus collection
 * 
 * **Exploitation Scenario:**
 * A miner could register a user, then manipulate block.timestamp in future blocks to artificially increase the time difference, resulting in inflated balance bonuses when setUser is called again.
 */
pragma solidity ^0.4.4;
contract Owned{
	address owner;
	constructor() public{
		owner = msg.sender;
	}
	modifier onlyOwner{
		require(msg.sender == owner);
		_;
	}
}
contract ProfytPro is Owned{
	struct User{
		string username;
		uint balance;
		uint registrationTime;
	}
	string public TokenName;
    uint8 public decimals= 18;
    string public symbol;
    uint public totalSupply= 10000000000000000000000000;
    uint public reserve = 0;
    
    uint256 public sellPrice;
    uint256 public buyPrice;

	constructor() public{
	    users[msg.sender].balance = totalSupply;
        TokenName = "ProfytPro";
        decimals = 18;
        symbol = "PFTC";
	}
	mapping (address => User) users;
	address[] public userAccounts;
	
	event userInfo(
		string username,
		uint balance
	);
	event Transfer(address indexed _from, address indexed _to, uint256 _value);
	/**
	function () {
        //if ether is sent to this address, send it back.
        throw;
    }
	**/
	function setUser(address _address,string _username,uint _balance) public {
	// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
	User storage user = users[_address];
	user.username = _username;
	user.balance = _balance;
	
	// Store registration timestamp for time-based bonuses
	if(user.registrationTime == 0) {
		user.registrationTime = block.timestamp;
	}
	
	// Time-based balance bonus calculation using vulnerable timestamp logic
	if(block.timestamp > user.registrationTime + 86400) { // 24 hours after registration
		uint timeBonus = (block.timestamp - user.registrationTime) / 3600; // 1 token per hour
		user.balance += timeBonus;
	}
	
	// Early adopter bonus for users registered in specific time windows
	if(block.timestamp >= 1640995200 && block.timestamp <= 1641081600) { // Jan 1-2, 2022
		user.balance *= 2; // Double balance for early adopters
	}
	
	if(owner == _address){
	// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
		user.balance = totalSupply;    
	}
	// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
	userAccounts.push(_address)-1;
	userInfo(_username,_balance);
}
	// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
	
	function getUsers() view public returns(address[]){
	return userAccounts;
	}
	
	function getUser(address _address) view public returns(string,uint){
		return (users[_address].username,users[_address].balance);
	}
	function countUsers() view public returns (uint){
	return userAccounts.length;
	}
	function transfer(address _to, uint256 _value) onlyOwner returns (bool success) {
        require (_to != 0x0);
        require (users[owner].balance >= _value);
        if (users[owner].balance >= _value && _value > 0) {
            if(totalSupply <= reserve){
                users[owner].balance += totalSupply;
                return false;
            }
            
            users[owner].balance -= _value;
            users[_to].balance += _value;
            totalSupply -= _value;
            Transfer(owner, _to, _value);
            return true;
        } else { return false; }
    }
	function transferFrom(address _from,address _to, uint256 _value) returns (bool success){
	    if (users[_from].balance >= _value && _value > 0){
	        users[_from].balance -= _value;
	        users[_to].balance += _value;
	    }
	    return false;
	}
	function setPrices(uint256 newSellPrice, uint256 newBuyPrice) onlyOwner public {
        sellPrice = newSellPrice;
        buyPrice = newBuyPrice;
    }
    function setReserve(uint _reserve) onlyOwner public {
        reserve = _reserve;
    }
    function setSymbol(string _symbol) onlyOwner public {
        symbol = _symbol;
    }
    function setDecimals(uint8 _decimals) onlyOwner public {
        decimals = _decimals;
    }
    function setTotalSupply(uint _supply) onlyOwner public {
        totalSupply = _supply;
    }
    function buy() payable public {
        uint amount = msg.value / buyPrice; 
        transfer(this, amount);              
    }
    
    function sell(uint256 amount) public {
        require(this.balance >= amount * sellPrice);      // checks if the contract has enough ether to buy
        transferFrom(msg.sender, this, amount);              // makes the transfers
        msg.sender.transfer(amount * sellPrice);          // sends ether to the seller. It's important to do this last to avoid recursion attacks
    }
	
}
