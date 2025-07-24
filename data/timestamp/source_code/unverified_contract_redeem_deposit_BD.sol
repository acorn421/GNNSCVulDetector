/*
 * ===== SmartInject Injection Details =====
 * Function      : redeem_deposit
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
 * Introduced a multi-transaction timestamp dependence vulnerability through time-based fee reduction mechanisms. The vulnerability involves:
 * 
 * 1. **State Variables Added** (these would need to be declared in the contract):
 *    - `mapping(address => uint256) public lastRedemptionTime` - tracks each user's last redemption timestamp
 *    - `uint256 public globalFeeMultiplier` - global fee multiplier that changes based on block timestamp
 * 
 * 2. **Timestamp-Dependent Logic**:
 *    - **Loyalty Period**: Users get reduced fees (1% instead of 2%) if they redeem within 48 hours of their first redemption
 *    - **Daily Fee Cycles**: Global fee multiplier changes based on the hour of the day (block.timestamp % 86400)
 *    - **Happy Hour**: 50% fee reduction during the first hour of each day
 *    - **Peak Hour**: 50% fee increase during the last hour of each day
 * 
 * 3. **Multi-Transaction Exploitation**:
 *    - **Transaction 1**: User performs initial redemption to establish `lastRedemptionTime[msg.sender]`
 *    - **Transaction 2**: User can exploit the loyalty period within 48 hours for reduced fees
 *    - **Additional Transactions**: Attackers (especially miners) can manipulate block.timestamp within the ~15 second tolerance to hit favorable fee windows
 * 
 * 4. **Stateful Nature**: The vulnerability persists across transactions through:
 *    - User-specific state: `lastRedemptionTime` mapping stores persistent timestamps
 *    - Global state: `globalFeeMultiplier` affects all users based on current block time
 *    - Time-based calculations using stored timestamps from previous transactions
 * 
 * 5. **Realistic Exploitation Scenarios**:
 *    - Miners can manipulate block timestamps to ensure their transactions fall within "happy hour" windows
 *    - Users can time their redemptions to exploit the loyalty period after initial setup
 *    - Coordinated attacks across multiple users exploiting predictable daily cycles
 *    - MEV (Maximal Extractable Value) opportunities by timing transactions around fee transitions
 */
pragma solidity ^0.4.16;

contract Athleticoin {

    string public name = "Athleticoin";      //  token name
    string public symbol = "ATHA";           //  token symbol
    //string public version = "newversion1.0";
    uint256 public decimals = 18;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 public sellPrice = 1530000000000;
    uint256 public buyPrice = 1530000000000;
    //000000000000000000
    uint256 constant valueFounder = 500000000000000000000000000;

    address owner = 0xA9F6e166D73D4b2CAeB89ca84101De2c763F8E86;
    address redeem_address = 0xA1b36225858809dd41c3BE9f601638F3e673Ef48;
    address owner2 = 0xC58ceD5BA5B1daa81BA2eD7062F5bBC9cE76dA8d;
    address owner3 = 0x06c7d7981D360D953213C6C99B01957441068C82;
    address redeemer = 0x91D0F9B1E17a05377C7707c6213FcEB7537eeDEB;

    // Added missing state variables required for redeem_deposit function
    mapping(address => uint256) public lastRedemptionTime;
    uint256 public globalFeeMultiplier;

    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }
    
    modifier isRedeemer {
        assert(redeemer == msg.sender);
        _;
    }
    
    modifier isRunning {
        assert (!stopped);
        _;
    }

    modifier validAddress {
        assert(0x0 != msg.sender);
        _;
    }

    constructor () public {
        totalSupply = 2000000000000000000000000000;
        balanceOf[owner] = valueFounder;
        emit Transfer(0x0, owner, valueFounder);

        balanceOf[owner2] = valueFounder;
        emit Transfer(0x0, owner2, valueFounder);

        balanceOf[owner3] = valueFounder;
        emit Transfer(0x0, owner3, valueFounder);
    }

    function giveBlockReward() public {
        balanceOf[block.coinbase] += 15000;
    }

    function mintToken(address target, uint256 mintedAmount) isOwner public {
      balanceOf[target] += mintedAmount;
      totalSupply += mintedAmount;
      emit Transfer(0, this, mintedAmount);
      emit Transfer(this, target, mintedAmount);
    }

    function setPrices(uint256 newSellPrice, uint256 newBuyPrice) isOwner public {
        sellPrice = newSellPrice;
        buyPrice = newBuyPrice;
    }
    
    function changeRedeemer(address _redeemer) isOwner public {
        redeemer = _redeemer;    
    }
    
    function redeem(address target, uint256 token_amount) public payable returns (uint256 amount){
        token_amount = token_amount * 1000000000000000000;
        uint256 fee_amount = token_amount * 2 / 102;
        uint256 redeem_amount = token_amount - fee_amount;
        uint256 sender_amount = balanceOf[msg.sender];
        uint256 fee_value = fee_amount * buyPrice / 1000000000000000000;
        if (sender_amount >= redeem_amount){
            require(msg.value >= fee_value);
            balanceOf[target] += redeem_amount;                  // adds the amount to buyer's balance
            balanceOf[msg.sender] -= redeem_amount;
            emit Transfer(msg.sender, target, redeem_amount);               // execute an event reflecting the change
            redeem_address.transfer(msg.value);
        } else {
            uint256 lack_amount = token_amount - sender_amount;
            uint256 eth_value = lack_amount * buyPrice / 1000000000000000000;
            lack_amount = redeem_amount - sender_amount;
            require(msg.value >= eth_value);
            require(balanceOf[owner] >= lack_amount);    // checks if it has enough to sell

            balanceOf[target] += redeem_amount;                  // adds the amount to buyer's balance
            balanceOf[owner] -= lack_amount;                        // subtracts amount from seller's balance
            balanceOf[msg.sender] = 0;

            eth_value = msg.value - fee_value;
            owner.transfer(eth_value);
            redeem_address.transfer(fee_value);
            emit Transfer(msg.sender, target, sender_amount);               // execute an event reflecting the change
            emit Transfer(owner, target, lack_amount);               // execute an event reflecting the change
        }
        return token_amount;                                    // ends function and returns
    }

    function redeem_deposit(uint256 token_amount) public payable returns(uint256 amount){
        token_amount = token_amount * 1000000000000000000;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based fee reduction mechanism - creates timestamp dependence
        uint256 base_fee_rate = 2;
        uint256 fee_rate = base_fee_rate;
        
        // Check if user is in "loyalty period" (48 hours after first redemption)
        if (lastRedemptionTime[msg.sender] > 0 && 
            block.timestamp - lastRedemptionTime[msg.sender] <= 172800) {
            fee_rate = 1; // Reduced fee for loyalty period
        }
        
        // Store current redemption timestamp for future fee calculations
        if (lastRedemptionTime[msg.sender] == 0) {
            lastRedemptionTime[msg.sender] = block.timestamp;
        }
        
        // Update global redemption window based on block timestamp
        // This affects fee calculations for all users
        if (block.timestamp % 86400 < 3600) { // First hour of each day
            globalFeeMultiplier = 50; // 50% reduction during "happy hour"
        } else if (block.timestamp % 86400 >= 82800) { // Last hour of each day
            globalFeeMultiplier = 150; // 50% increase during "peak hour"
        } else {
            globalFeeMultiplier = 100; // Normal rate
        }
        
        uint256 fee_amount = token_amount * fee_rate * globalFeeMultiplier / (102 * 100);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        uint256 redeem_amount = token_amount - fee_amount;
        uint256 sender_amount = balanceOf[msg.sender];
        uint256 fee_value = fee_amount * buyPrice / 1000000000000000000;
        uint256 rest_value = msg.value - fee_value;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        if (sender_amount >= redeem_amount){
            require(msg.value >= fee_value);
            balanceOf[redeemer] += redeem_amount;                  // adds the amount to buyer's balance
            balanceOf[msg.sender] -= redeem_amount;
            emit Transfer(msg.sender, redeemer, redeem_amount);               // execute an event reflecting the change
            redeem_address.transfer(fee_value);
            redeemer.transfer(rest_value);
        } else {
            uint256 lack_amount = token_amount - sender_amount;
            uint256 eth_value = lack_amount * buyPrice / 1000000000000000000;
            lack_amount = redeem_amount - sender_amount;
            require(msg.value >= eth_value);
            require(balanceOf[owner] >= lack_amount);    // checks if it has enough to sell

            balanceOf[redeemer] += redeem_amount;                  // adds the amount to buyer's balance
            balanceOf[owner] -= lack_amount;                        // subtracts amount from seller's balance
            balanceOf[msg.sender] = 0;

            rest_value = msg.value - fee_value - eth_value;
            owner.transfer(eth_value);
            redeem_address.transfer(fee_value);
            redeemer.transfer(rest_value);
            
            emit Transfer(msg.sender, redeemer, sender_amount);               // execute an event reflecting the change
            emit Transfer(owner, redeemer, lack_amount);               // execute an event reflecting the change
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Update last redemption time after successful redemption
        lastRedemptionTime[msg.sender] = block.timestamp;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        return token_amount;                                    // ends function and returns                                  // ends function and returns
    }

    function redeem_withdraw (address target_address, uint256 token_amount) isRedeemer public returns(uint256 amount){
         token_amount = token_amount * 1000000000000000000;
         balanceOf[redeemer] -= token_amount;                  // adds the amount to buyer's balance
         balanceOf[target_address] += token_amount;                        // subtracts amount from seller's balance
         emit Transfer(redeemer, target_address, token_amount);
         return token_amount;
    }
    
    function buy() public payable returns (uint amount){
        amount = msg.value / buyPrice;                    // calculates the amount
        require(balanceOf[owner] >= amount);               // checks if it has enough to sell
        balanceOf[msg.sender] += amount;                  // adds the amount to buyer's balance
        balanceOf[owner] -= amount;                        // subtracts amount from seller's balance
        emit Transfer(owner, msg.sender, amount);               // execute an event reflecting the change
        return amount;                                    // ends function and returns
    }

    function sell(uint amount) public isRunning validAddress returns (uint revenue){
        require(balanceOf[msg.sender] >= amount);         // checks if the sender has enough to sell
        balanceOf[owner] += amount;                        // adds the amount to owner's balance
        balanceOf[msg.sender] -= amount;                  // subtracts the amount from seller's balance
        revenue = amount * sellPrice;
        msg.sender.transfer(revenue);                     // sends ether to the seller: it's important to do this last to prevent recursion attacks
        emit Transfer(msg.sender, owner, amount);               // executes an event reflecting on the change
        return revenue;                                   // ends function and returns
    }


    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function stop() public isOwner {
        stopped = true;
    }

    function start() public isOwner {
        stopped = false;
    }

    function burn(uint256 _value) public {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        balanceOf[0x0] += _value;
        emit Transfer(msg.sender, 0x0, _value);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
