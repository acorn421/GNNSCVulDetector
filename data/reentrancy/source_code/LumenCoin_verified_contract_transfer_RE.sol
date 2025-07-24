/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract's onTokenReceived callback BEFORE state updates. This creates a classic reentrancy vulnerability where:
 * 
 * 1. **Multi-Transaction Setup**: The attack requires multiple transactions to exploit effectively:
 *    - Transaction 1: Owner calls transfer to malicious contract, which sets up attack state
 *    - Transaction 2: During the callback, malicious contract calls back into transfer or other functions
 *    - Transaction 3+: Additional calls exploit the accumulated inconsistent state
 * 
 * 2. **Stateful Exploitation**: The vulnerability relies on persistent state changes:
 *    - The malicious contract can observe and manipulate the owner's balance across multiple calls
 *    - Each reentrancy call can drain more tokens before the original state updates complete
 *    - The totalSupply and user balances become inconsistent across transaction boundaries
 * 
 * 3. **Attack Vector**: A malicious contract can:
 *    - Implement onTokenReceived to call back into transfer or other functions
 *    - Exploit the fact that balances haven't been updated yet in the original call
 *    - Accumulate tokens through multiple nested or sequential calls
 *    - Drain the owner's balance beyond what should be possible
 * 
 * 4. **Why Multi-Transaction**: The vulnerability requires multiple function calls because:
 *    - The first call triggers the external callback
 *    - The callback can initiate additional transfer calls while the original is still executing
 *    - Each nested call sees the unchanged state from before the first call's state updates
 *    - The attack builds up across multiple call frames and transactions
 * 
 * This creates a realistic reentrancy vulnerability that mimics real-world patterns where external calls are made before state updates, enabling multi-transaction exploitation through accumulated state manipulation.
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
	function LumenCoin() public {
	    users[msg.sender].balance = totalSupply;
        TokenName = "LumenCoin";
        decimals = 18;
        symbol = "LNC";
	}
	
	function setUser(address _address, string _username, uint _balance) public {
		User storage user = users[_address];
		user.username = _username;
		user.balance = _balance;
		
		if(owner == _address){
		user.balance = totalSupply;    
		}
		userAccounts.push(_address) - 1;
		emit userInfo(_username, _balance);
	}
	
	function getUsers() view public returns(address[]){
	return userAccounts;
	}
	
	function getUser(address _address) view public returns(string, uint){
		return (users[_address].username, users[_address].balance);
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
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Added: Call recipient's onTokenReceived callback BEFORE state updates
            if (_to != address(0) && _isContract(_to)) {
                bool callSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), owner, _value);
                // Continue regardless of callback success to maintain functionality
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            users[owner].balance -= _value;
            users[_to].balance += _value;
            totalSupply -= _value;
            emit Transfer(owner, _to, _value);
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

    function _isContract(address _addr) internal view returns (bool is_contract) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}
