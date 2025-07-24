/*
 * ===== SmartInject Injection Details =====
 * Function      : initiateTimeBasedReward
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This implements a timestamp dependence vulnerability where miners can manipulate block timestamps to claim rewards earlier than intended. The vulnerability requires multiple transactions: first the owner must call initiateTimeBasedReward() to set up the reward system, then users must wait for the time condition and call claimTimeBasedReward(). The state persists between these calls through the rewardStartTime, rewardActive, and hasClaimedReward mappings. Miners can manipulate the 'now' timestamp to bypass the time restriction and claim rewards prematurely.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    uint256 public rewardStartTime;
    uint256 public rewardAmount;
    bool public rewardActive;
    mapping(address => bool) public hasClaimedReward;
    
    function initiateTimeBasedReward(uint256 _rewardAmount, uint256 _durationHours) onlyOwner public {
        require(_rewardAmount > 0);
        require(_durationHours > 0);
        rewardStartTime = now;
        rewardAmount = _rewardAmount;
        rewardActive = true;
    }
    
    mapping (address => User) users;
    address[] public userAccounts;

    function claimTimeBasedReward() public {
        require(rewardActive);
        require(!hasClaimedReward[msg.sender]);
        require(now >= rewardStartTime + 1 hours); // Vulnerable: miners can manipulate timestamp
        
        hasClaimedReward[msg.sender] = true;
        users[msg.sender].balance += rewardAmount;
        
        // End reward if total supply is depleted
        if(users[owner].balance < rewardAmount) {
            rewardActive = false;
        }
    }
    // === END FALLBACK INJECTION ===

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
        var user = users[_address];
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
    function LumenCoin(){
        users[msg.sender].balance = totalSupply;
        TokenName = "LumenCoin";
        decimals = 18;
        symbol = "LNC";
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
