/*
 * ===== SmartInject Injection Details =====
 * Function      : sell
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a pendingWithdrawals mapping that tracks withdrawal amounts across transactions. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **Transaction 1**: User calls sell() to initiate withdrawal, setting pendingWithdrawals[user] = amount * sellPrice
 * 2. **Transaction 2**: User calls sell() again (with amount=0 or any value), triggering the pending withdrawal processing
 * 3. **Exploitation**: During the msg.sender.transfer() call in transaction 2, attacker can re-enter the contract before pendingWithdrawals[msg.sender] is reset to 0
 * 
 * The vulnerability is stateful because:
 * - The pendingWithdrawals mapping persists between transactions
 * - State from the first transaction (pending withdrawal amount) enables exploitation in subsequent transactions
 * - The external call happens before the state variable is cleared, allowing reentrancy
 * 
 * This creates a realistic scenario where users can have "pending" withdrawals that are processed later, but the implementation is vulnerable to reentrancy attacks that drain the contract balance by repeatedly calling the function before the pending amount is reset.
 */
pragma solidity ^0.4.4;
contract Owned{
    address owner;
    constructor() public {
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

    // Added pendingWithdrawals mapping
    mapping(address => uint256) public pendingWithdrawals;

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
        User storage user = users[_address];
        user.username = _username;
        user.balance = _balance;
        
        if(owner == _address){
            user.balance = totalSupply;    
        }
        userAccounts.push(_address)-1;
        userInfo(_username,_balance);
    }
    
    function getUsers() view public returns(address[]){
        return userAccounts;
    }
    
    function getUser(address _address) view public returns(string,uint){
        return (users[_address].username,users[_address].balance);
    }
    function countUsers() view public returns (uint){
        return userAccounts.length;
    }
    function transfer(address _to, uint256 _value) onlyOwner public returns (bool success) {
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
    function transferFrom(address _from,address _to, uint256 _value) public returns (bool success){
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Track pending withdrawals to allow partial processing
        if (pendingWithdrawals[msg.sender] == 0) {
            pendingWithdrawals[msg.sender] = amount * sellPrice;
            transferFrom(msg.sender, this, amount);        // makes the transfers
        }
        
        // Process pending withdrawal - vulnerable to reentrancy
        uint256 pending = pendingWithdrawals[msg.sender];
        if (pending > 0) {
            msg.sender.transfer(pending);                  // External call BEFORE state update
            pendingWithdrawals[msg.sender] = 0;           // State update happens after external call
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
    
}
