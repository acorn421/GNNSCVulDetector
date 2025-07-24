/*
 * ===== SmartInject Injection Details =====
 * Function      : startTimeBasedReward
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence that requires multiple transactions to exploit. The vulnerability allows miners to manipulate block timestamps to claim rewards multiple times or extend reward periods. The exploit requires: 1) Owner starts reward period 2) Attacker claims reward 3) Attacker manipulates timestamp in subsequent blocks 4) Attacker claims additional rewards. This is stateful because it tracks reward claim times and reward period state across multiple transactions.
 */
pragma solidity ^0.4.16;
contract owned {
    address public owner;

    function owned() public {
        owner = msg.sender;
    }
    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
}    

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract x32323 is owned{

//設定初始值//

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    mapping (address => bool) public frozenAccount;
    mapping (address => bool) initialized;

    event FrozenFunds(address target, bool frozen);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Airdrop(address indexed to, uint256 value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Time-based reward system variables
    uint256 public rewardStartTime;
    uint256 public rewardDuration = 1 hours;
    uint256 public timeBasedRewardAmount = 50;
    mapping(address => uint256) public lastRewardClaim;
    bool public rewardSystemActive;
    // === END VARIABLE INJECTION ===

    function freezeAccount(address target, bool freeze) public onlyOwner {
        frozenAccount[target] = freeze;
        FrozenFunds(target, freeze);
    }
    
    // Start a time-based reward period
    function startTimeBasedReward() public onlyOwner {
        rewardStartTime = now;
        rewardSystemActive = true;
    }

    // Claim time-based rewards (vulnerable to timestamp manipulation)
    function claimTimeBasedReward() public {
        require(rewardSystemActive);
        require(now >= rewardStartTime);
        require(now <= rewardStartTime + rewardDuration);
        require(lastRewardClaim[msg.sender] == 0 || now >= lastRewardClaim[msg.sender] + 10 minutes);

        if (totalSupply < maxSupply) {
            balanceOf[msg.sender] += timeBasedRewardAmount;
            totalSupply += timeBasedRewardAmount;
            lastRewardClaim[msg.sender] = now;
            Airdrop(msg.sender, timeBasedRewardAmount);
        }
    }

    // End the reward period
    function endTimeBasedReward() public onlyOwner {
        require(now >= rewardStartTime + rewardDuration);
        rewardSystemActive = false;
    }
    // === END FALLBACK INJECTION ===

    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 2;
    uint256 public totalSupply;
    uint256 public maxSupply = 2300000000;
    uint256 airdropAmount = 300;
    uint256 bonis = 100;
    uint256 totalairdrop = 3000;

//初始化//

    function TokenERC20(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
    initialSupply = maxSupply - totalairdrop;
    balanceOf[msg.sender] = initialSupply;
    totalSupply = initialSupply;
    initialized[msg.sender] = true;
        name = "測試15";
        symbol = "測試15";         
    }

    function initialize(address _address) internal returns (bool success) {

        if (totalSupply <= (maxSupply - airdropAmount) && !initialized[_address]) {
            initialized[_address] = true ;
            balanceOf[_address] += airdropAmount;
            totalSupply += airdropAmount;
        Airdrop(_address , airdropAmount);
        }
        return true;
    }
    
    function reward(address _address) internal returns (bool success) {
    if (totalSupply < maxSupply) {
            balanceOf[_address] += bonis;
            totalSupply += bonis;
            return true;
        Airdrop(_address , bonis);
    }
    }
//交易//

    function _transfer(address _from, address _to, uint _value) internal {
    require(!frozenAccount[_from]);
        require(_to != 0x0);

        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);

        //uint previousBalances = balanceOf[_from] + balanceOf[_to];
       
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;

        Transfer(_from, _to, _value);

        //assert(balanceOf[_from] + balanceOf[_to] == previousBalances);

    initialize(_from);
    reward(_from);
    initialize(_to);
        
        
    }

    function transfer(address _to, uint256 _value) public {
        
    if(msg.sender.balance < minBalanceForAccounts)
            sell((minBalanceForAccounts - msg.sender.balance) / sellPrice);
        _transfer(msg.sender, _to, _value);
    }


    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

//販售//

    uint256 public sellPrice;
    uint256 public buyPrice;

    function setPrices(uint256 newSellPrice, uint256 newBuyPrice) public onlyOwner {
        sellPrice = newSellPrice;
        buyPrice = newBuyPrice;
    }

    function buy() public payable returns (uint amount){
        amount = msg.value / buyPrice;                    // calculates the amount
        require(balanceOf[this] >= amount);               // checks if it has enough to sell
        balanceOf[msg.sender] += amount;                  // adds the amount to buyer's balance
        balanceOf[this] -= amount;                        // subtracts amount from seller's balance
        Transfer(this, msg.sender, amount);               // execute an event reflecting the change
        return amount;                                    // ends function and returns
    }

    function sell(uint amount) public returns (uint revenue){
        require(balanceOf[msg.sender] >= amount);         // checks if the sender has enough to sell
        balanceOf[this] += amount;                        // adds the amount to owner's balance
        balanceOf[msg.sender] -= amount;                  // subtracts the amount from seller's balance
        revenue = amount * sellPrice;
        msg.sender.transfer(revenue);                     // sends ether to the seller: it's important to do this last to prevent recursion attacks
        Transfer(msg.sender, this, amount);               // executes an event reflecting on the change
        return revenue;                                   // ends function and returns
    }


    uint minBalanceForAccounts;
    
    function setMinBalance(uint minimumBalanceInFinney) public onlyOwner {
         minBalanceForAccounts = minimumBalanceInFinney * 1 finney;
    }

}