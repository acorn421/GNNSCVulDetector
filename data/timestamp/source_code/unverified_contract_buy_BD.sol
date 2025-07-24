/*
 * ===== SmartInject Injection Details =====
 * Function      : buy
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
 * Introduced a multi-transaction timestamp dependence vulnerability by adding:
 * 
 * 1. **Dynamic Price Updates**: The buyPrice is now updated based on block.timestamp, with volatility increasing over time. This creates arbitrage opportunities where miners can manipulate timestamps to get favorable prices.
 * 
 * 2. **Time-based Loyalty Bonus**: Users receive bonus tokens based on time elapsed since their last purchase, calculated using block.timestamp. This creates a multi-transaction vulnerability where:
 *    - Transaction 1: User makes initial purchase, establishing their timestamp baseline
 *    - Transaction 2+: User (or miner) can manipulate block.timestamp to artificially increase the time gap and receive larger bonuses
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Setup Phase**: User makes first purchase to establish userLastPurchase[msg.sender] timestamp
 * 2. **Accumulation Phase**: Miner or user waits and manipulates subsequent block timestamps
 * 3. **Exploitation Phase**: User makes second purchase with manipulated timestamp to receive inflated bonus multiplier
 * 4. **Repeated Exploitation**: Process can be repeated across multiple transactions to accumulate excessive tokens
 * 
 * **Required State Variables** (to be added to contract):
 * - `uint256 public lastPriceUpdate`
 * - `uint256 public baseBuyPrice` 
 * - `uint256 public priceVolatility`
 * - `mapping(address => uint256) public userLastPurchase`
 * 
 * The vulnerability requires multiple transactions because the exploitation depends on the time difference between purchases, making it impossible to exploit in a single atomic transaction. The state persists between calls, allowing for gradual accumulation of advantages through timestamp manipulation.
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

    function freezeAccount(address target, bool freeze) public onlyOwner {
        frozenAccount[target] = freeze;
        FrozenFunds(target, freeze);
    }

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
    uint256 public lastPriceUpdate;
    uint256 public priceVolatility;
    uint256 public baseBuyPrice;
    mapping(address => uint256) public userLastPurchase;

    function setPrices(uint256 newSellPrice, uint256 newBuyPrice) public onlyOwner {
        sellPrice = newSellPrice;
        buyPrice = newBuyPrice;
    }

    function buy() public payable returns (uint amount){
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Update buy price based on time volatility - vulnerable to timestamp manipulation
        if (block.timestamp >= lastPriceUpdate + 300) { // 5 minute price updates
            uint256 timeElapsed = block.timestamp - lastPriceUpdate;
            // Price becomes more volatile over time, creating arbitrage opportunities
            uint256 volatilityFactor = (timeElapsed * priceVolatility) / 1000;
            buyPrice = baseBuyPrice + volatilityFactor;
            lastPriceUpdate = block.timestamp;
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        amount = msg.value / buyPrice;                    // calculates the amount
        require(balanceOf[this] >= amount);               // checks if it has enough to sell
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Track user purchase history for "loyalty bonus" - exploitable timing
        if (userLastPurchase[msg.sender] == 0) {
            userLastPurchase[msg.sender] = block.timestamp;
        } else {
            uint256 timeSinceLastPurchase = block.timestamp - userLastPurchase[msg.sender];
            // Bonus increases with longer time gaps - manipulable by miners
            if (timeSinceLastPurchase >= 3600) { // 1 hour bonus threshold
                uint256 bonusMultiplier = (timeSinceLastPurchase / 3600) + 1;
                if (bonusMultiplier > 5) bonusMultiplier = 5; // Cap at 5x
                amount = amount * bonusMultiplier;
            }
            userLastPurchase[msg.sender] = block.timestamp;
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
