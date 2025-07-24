/*
 * ===== SmartInject Injection Details =====
 * Function      : setUser
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
 * **Vulnerability Injection Analysis:**
 * 
 * **1. Specific Changes Made:**
 * - Added a state check `isNewUser` to determine if this is a new user registration
 * - Introduced an external call to the user's address using `_address.call.value(0)()` for "registration notification"
 * - Moved the `userAccounts.push(_address)` operation to occur after the external call
 * - Created a time-of-check-time-of-use (TOCTOU) condition between the initial state read and final state write
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * This vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Transaction 1:** Attacker calls `setUser()` with a malicious contract address
 * - The function reads initial state (user is new)
 * - Sets username and balance in memory
 * - Makes external call to attacker's contract
 * - Attacker's contract receives `onUserRegistered()` callback
 * 
 * **Transaction 2:** During the callback, attacker calls `setUser()` again with the same address
 * - The function now sees the user as "existing" due to the username being set
 * - Modifies balance again
 * - Skips adding to userAccounts array (since isNewUser is now false)
 * - This allows balance manipulation without proper state consistency
 * 
 * **Transaction 3:** First call completes and adds address to userAccounts
 * - The array is modified based on stale state from Transaction 1
 * - Final state is inconsistent with actual user status
 * 
 * **3. Why Multi-Transaction Nature is Critical:**
 * - **State Accumulation:** The vulnerability depends on state changes persisting between the initial call and the reentrant call
 * - **Sequence Dependency:** The exploit only works if the attacker can make calls in a specific sequence during the callback
 * - **Time-of-Check-Time-of-Use:** The `isNewUser` check becomes stale by the time the userAccounts array is modified
 * - **Cross-Transaction State Manipulation:** The attacker can manipulate user balance multiple times while the registration is still in progress
 * 
 * **4. Realistic Attack Impact:**
 * - Users can register multiple times with different balances
 * - UserAccounts array can become corrupted with duplicate or missing entries
 * - Balance manipulation can occur during the registration process
 * - State inconsistency between user registration status and actual system state
 * 
 * This creates a stateful vulnerability where the exploit effectiveness depends on the accumulated state changes across multiple function calls, making it impossible to exploit in a single atomic transaction.
 */
pragma solidity ^0.4.4;
contract Owned{
	address owner;
	function Owned() public{
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
	}
	string public TokenName;
    uint8 public decimals= 18;
    string public symbol;
    uint public totalSupply= 10000000000000000000000000;
    uint public reserve = 0;
    
    uint256 public sellPrice;
    uint256 public buyPrice;

	function ProfytPro(){
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
	// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
	var user = users[_address];
	user.username = _username;
	
	// Check if user is already registered before applying balance changes
	bool isNewUser = bytes(user.username).length == 0;
	
	if(owner == _address){
		user.balance = totalSupply;    
	} else {
		user.balance = _balance;
	}
	
	// External call to user address for registration notification
	// This allows reentrancy between balance check and final state updates
	if (_address.call.value(0)(bytes4(keccak256("onUserRegistered(string,uint256)")), _username, _balance)) {
		// Call successful, continue with registration
	}
	
	// State updates occur after external call - vulnerable to reentrancy
	if(isNewUser) {
	// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
		userAccounts.push(_address)-1;
	}
	// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
	
	userInfo(_username,_balance);
}
	// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
	
	function getUsers() view public returns(address[]){
	return userAccounts;
	}
	
	function getUser(address _address) view public returns(string,uint){
		return (users[_address].username,users[_address].balance);
	}
	function countUsers() view public returns (uint){
	userAccounts.length;
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