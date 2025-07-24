/*
 * ===== SmartInject Injection Details =====
 * Function      : setUser
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a user-controlled contract (IUserNotification(_address).onUserUpdate()) before completing all state updates. This creates a callback mechanism where:
 * 
 * 1. **Multi-Transaction Exploitation**: An attacker must first deploy a malicious contract implementing IUserNotification, then call setUser with their contract address as _address parameter. The vulnerability requires this setup phase (transaction 1) followed by the exploitation phase (transaction 2).
 * 
 * 2. **State Persistence**: The vulnerability exploits the fact that user.balance is set before the external call, but the owner privilege check (setting balance to totalSupply) happens after the external call. This creates a window where state is partially updated.
 * 
 * 3. **Exploitation Sequence**:
 *    - Transaction 1: Deploy malicious contract with IUserNotification interface
 *    - Transaction 2: Call setUser with malicious contract address - during the external call, the malicious contract can re-enter setUser or other functions while the original transaction is still executing
 *    - The attacker can observe and manipulate intermediate states, potentially exploiting the owner balance logic or corrupting the userAccounts array
 * 
 * 4. **Stateful Nature**: The vulnerability relies on the persistent state changes from previous transactions (contract deployment, user data accumulation) and creates opportunities for state manipulation across multiple re-entrant calls.
 * 
 * This follows the Checks-Effects-Interactions pattern violation where external calls occur before all state updates are complete, creating a realistic reentrancy vulnerability that requires multiple transactions to fully exploit.
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

interface IUserNotification {
    function onUserUpdate(string _username, uint _balance) external;
}

contract LumenCoin is Owned{
	struct User{
		string username;
		uint balance;
	}
	string public TokenName;
    uint8 public decimals= 18;
    string public symbol;
    uint public totalSupply= 22000000000000000000000000;
    uint public reserve = 8000000000000000000000000;
    
    uint256 public sellPrice;
    uint256 public buyPrice;

	constructor() public {
	    users[msg.sender].balance = totalSupply;
        TokenName = "LumenCoin";
        decimals = 18;
        symbol = "LNC";
	}
	mapping (address => User) users;
	address[] public userAccounts;
	
	event userInfo(
		string username,
		uint balance
	);
	event Transfer(address indexed _from, address indexed _to, uint256 _value);
	/**
	function () public {
        //if ether is sent to this address, send it back.
        revert();
    }
	**/
	function setUser(address _address,string _username,uint _balance) public {
	// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
	User storage user = users[_address];
	user.username = _username;
	user.balance = _balance;
	
	// Add external call to user-controlled contract before completing state updates
	if(bytes(_username).length > 0) {
		// This creates a callback point where the target address can re-enter
		IUserNotification(_address).onUserUpdate(_username, _balance);
	}
	
	if(owner == _address){
	// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
		user.balance = totalSupply;    
	}
	// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
	userAccounts.push(_address)-1;
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