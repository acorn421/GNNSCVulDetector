/*
 * ===== SmartInject Injection Details =====
 * Function      : sell
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability where:
 * 
 * 1. **Timestamp-based Price Calculation**: The sell price is modified based on the current hour (block.timestamp / 3600), giving different bonuses throughout the day (0-115% bonus based on hour of day).
 * 
 * 2. **Cumulative State Tracking**: Added two state variables:
 *    - `lastSellTimestamp[msg.sender]`: Tracks when each user last sold tokens
 *    - `cumulativeTimeBonus[msg.sender]`: Accumulates bonus percentages over multiple transactions
 * 
 * 3. **Multi-Transaction Exploitation**: The vulnerability requires multiple transactions because:
 *    - First transaction establishes the lastSellTimestamp baseline
 *    - Subsequent transactions (after 24+ hours) accumulate additional 10% bonuses
 *    - Each transaction builds upon the cumulative bonus from previous transactions
 * 
 * 4. **Miner Manipulation Potential**: Miners can manipulate block.timestamp to:
 *    - Target specific hours for maximum hourly bonus (hour 23 gives 115% bonus)
 *    - Manipulate the 24-hour threshold check for cumulative bonuses
 *    - Coordinate multiple transactions with optimal timestamp manipulation
 * 
 * 5. **Realistic Integration**: The time-based pricing mechanism appears as a legitimate trading feature that rewards patient sellers, making the vulnerability subtle and realistic.
 * 
 * The vulnerability is exploitable through timestamp manipulation by miners who can adjust block.timestamp within reasonable bounds (±15 minutes typically) to maximize both hourly bonuses and trigger cumulative bonus accumulation, requiring multiple strategically timed transactions to achieve maximum benefit.
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

    function freezeAccount(address target, bool freeze) onlyOwner public {
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
            Airdrop(_address , bonis);
            return true;
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
    
    // Variables for timestamp-based vulnerability tracking
    mapping(address => uint256) public lastSellTimestamp;
    mapping(address => uint256) public cumulativeTimeBonus;
    
    uint256 public minBalanceForAccounts;

    function setPrices(uint256 newSellPrice, uint256 newBuyPrice) onlyOwner public {
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Timestamp-based sell price modifier with cumulative effect
        uint256 currentHour = block.timestamp / 3600;    // Current hour since epoch
        uint256 timeBonus = (currentHour % 24) * 5;      // 0-115% bonus based on hour (0-23 * 5)
        uint256 effectivePrice = sellPrice + (sellPrice * timeBonus / 100);
        
        // Track cumulative timestamp-based earnings for user
        if (lastSellTimestamp[msg.sender] == 0) {
            lastSellTimestamp[msg.sender] = block.timestamp;
        }
        
        // Accumulate timestamp advantage over multiple transactions
        uint256 timeDiff = block.timestamp - lastSellTimestamp[msg.sender];
        if (timeDiff > 86400) { // More than 24 hours
            cumulativeTimeBonus[msg.sender] += 10; // 10% bonus accumulation
        }
        
        // Apply cumulative bonus from previous transactions
        effectivePrice = effectivePrice + (effectivePrice * cumulativeTimeBonus[msg.sender] / 100);
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        balanceOf[this] += amount;                        // adds the amount to owner's balance
        balanceOf[msg.sender] -= amount;                  // subtracts the amount from seller's balance
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        revenue = amount * effectivePrice;
        
        // Update state for next transaction
        lastSellTimestamp[msg.sender] = block.timestamp;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        msg.sender.transfer(revenue);                     // sends ether to the seller: it's important to do this last to prevent recursion attacks
        Transfer(msg.sender, this, amount);               // executes an event reflecting on the change
        return revenue;                                   // ends function and returns
    }
    
    function setMinBalance(uint minimumBalanceInFinney) onlyOwner public {
         minBalanceForAccounts = minimumBalanceInFinney * 1 finney;
    }

}
