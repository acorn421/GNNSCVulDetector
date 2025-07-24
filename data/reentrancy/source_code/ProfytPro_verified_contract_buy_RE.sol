/*
 * ===== SmartInject Injection Details =====
 * Function      : buy
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
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a user-controlled purchase notification contract before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `IPurchaseNotifier(purchaseNotifier).notifyPurchase()` before the `transfer()` call
 * 2. Added `purchaseHistory[msg.sender] += amount` to track cumulative purchases (requires state variable)
 * 3. The external call occurs before critical state modifications in the `transfer()` function
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: Attacker calls `buy()` with malicious `purchaseNotifier` contract
 * 2. **Transaction 2**: During the external call, the malicious contract re-enters `buy()` while the original purchase is still processing
 * 3. **Transaction 3+**: The attacker can continue re-entering while the state is inconsistent, allowing them to purchase tokens at stale prices or bypass balance checks
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability depends on the persistent state of `purchaseHistory` mapping accumulating across calls
 * - The `purchaseNotifier` address must be set in a previous transaction (state setup)
 * - The exploit requires the attacker to control when re-entrancy occurs across multiple function invocations
 * - State inconsistencies build up across multiple transactions, making the attack more effective than single-transaction attempts
 * 
 * **Realistic Attack Scenario:**
 * The attacker would first set up a malicious notification contract, then call `buy()` multiple times where each call re-enters during the notification phase, allowing manipulation of the purchase logic while state is being modified.
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

interface IPurchaseNotifier {
    function notifyPurchase(address buyer, uint amount) external;
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

    // Added as per usage in 'buy'
    address public purchaseNotifier;
    mapping(address => uint) public purchaseHistory;
    
    mapping (address => User) users;
    address[] public userAccounts;
    
    event userInfo(
        string username,
        uint balance
    );
    event Transfer(address indexed _from, address indexed _to, uint256 _value);

    constructor() public {
        users[msg.sender].balance = totalSupply;
        TokenName = "ProfytPro";
        decimals = 18;
        symbol = "PFTC";
    }

    /**
    function () {
        //if ether is sent to this address, send it back.
        throw;
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
    function setPurchaseNotifier(address _notifier) onlyOwner public {
        purchaseNotifier = _notifier;
    }
    function buy() payable public {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        uint amount = msg.value / buyPrice;
        
        // Call external purchase notification contract before state updates
        if (purchaseNotifier != address(0)) {
            IPurchaseNotifier(purchaseNotifier).notifyPurchase(msg.sender, amount);
        }
        
        // Update purchase history for cumulative tracking
        purchaseHistory[msg.sender] += amount;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        transfer(this, amount);              
    }
    
    function sell(uint256 amount) public {
        require(this.balance >= amount * sellPrice);      // checks if the contract has enough ether to buy
        transferFrom(msg.sender, this, amount);              // makes the transfers
        msg.sender.transfer(amount * sellPrice);          // sends ether to the seller. It's important to do this last to avoid recursion attacks
    }
    
}