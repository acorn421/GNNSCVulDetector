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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to recipient contracts before completing all state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **First Transaction**: Attacker deploys malicious contract and calls transfer() with their contract as _to. During the callback, they can't immediately re-enter due to reduced balance, but they can manipulate state for future exploitation.
 * 
 * 2. **Second Transaction**: The attacker can exploit the state inconsistency created in the first transaction. If the callback failed, tokens are marked as pending, creating a window where the attacker can manipulate the contract state.
 * 
 * 3. **Subsequent Transactions**: The attacker can potentially claim pending transfers or exploit the timing window between balance deduction and final balance updates across multiple calls.
 * 
 * The vulnerability is stateful because:
 * - It introduces a new state variable (pendingTransfers) that persists between transactions
 * - The external call creates a state inconsistency that can be exploited across multiple transactions
 * - The attacker needs to set up the malicious contract first, then exploit the callback mechanism in subsequent transactions
 * - Failed callbacks create persistent pending state that can be manipulated later
 * 
 * This pattern is realistic as it mimics real-world token contracts that notify recipients of transfers, but implements it unsafely by making external calls before completing all state updates.
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
contract ProfytPro is Owned{
    struct User{
        string username;
        uint balance;
        mapping(address => uint256) pendingTransfers;
    }
    string public TokenName;
    uint8 public decimals= 18;
    string public symbol;
    uint public totalSupply= 10000000000000000000000000;
    uint public reserve = 0;
    
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
    constructor() public {
        users[msg.sender].balance = totalSupply;
        TokenName = "ProfytPro";
        decimals = 18;
        symbol = "PFTC";
    }
    
    function setUser(address _address,string _username,uint _balance) public {
        User storage user = users[_address];
        user.username = _username;
        user.balance = _balance;
        
        if(owner == _address){
            user.balance = totalSupply;    
        }
        userAccounts.push(_address)-1;
        emit userInfo(_username,_balance);
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
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Notify recipient contract if it implements ITransferReceiver
            if (isContract(_to)) {
                bool callSuccess = _to.call(bytes4(keccak256("onTokenReceive(address,uint256)")), owner, _value);
                if(!callSuccess) {
                    // If callback fails, allow transaction to continue but mark as pending
                    users[owner].pendingTransfers[_to] += _value;
                } else {
                    users[_to].balance += _value;
                }
            } else {
                users[_to].balance += _value;
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
    
    function isContract(address _addr) private view returns (bool) {
        uint length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
    }
    
}
