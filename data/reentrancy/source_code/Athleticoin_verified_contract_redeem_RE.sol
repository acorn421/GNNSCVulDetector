/*
 * ===== SmartInject Injection Details =====
 * Function      : redeem
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 4 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 * 3. reentrancy-events (SWC-107)
 * ... and 1 more
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added Withdrawal Tracking State Variables** (assumed to be declared in contract):
 *    - `mapping(address => uint256) withdrawal_attempts` - tracks number of redeem attempts per user
 *    - `mapping(address => uint256) withdrawal_amounts` - tracks total withdrawn amounts per user  
 *    - `uint256 max_withdrawal_per_user` - maximum withdrawal limit per user
 * 
 * 2. **Added External Call Before State Updates**: 
 *    - Introduced `target.call("")` before critical state changes to balanceOf mappings
 *    - This creates a reentrancy entry point that can be exploited
 * 
 * 3. **Created Multi-Transaction Exploitation Path**:
 *    - The withdrawal limit only applies after 3 attempts, creating a "warm-up" period
 *    - State variables persist between transactions, enabling accumulated exploitation
 *    - An attacker can manipulate withdrawal_attempts and withdrawal_amounts across multiple transactions
 * 
 * **Multi-Transaction Exploitation Scenario**:
 * 
 * **Transaction 1-3 (Setup Phase)**: 
 * - Attacker calls redeem() normally 3 times to build up withdrawal_attempts[attacker] = 3
 * - No withdrawal limits are enforced during this phase
 * - Attacker accumulates some withdrawal_amounts[attacker] value
 * 
 * **Transaction 4+ (Exploitation Phase)**:
 * - Attacker deploys a malicious contract as the target address
 * - Malicious contract's fallback function calls redeem() recursively when target.call("") is executed
 * - During reentrancy, withdrawal_attempts and withdrawal_amounts are checked using stale values
 * - Attacker can bypass withdrawal limits by exploiting the timing between the external call and state updates
 * - Each reentrant call sees the old withdrawal_amounts value before it's updated
 * - This allows draining more tokens than the max_withdrawal_per_user limit
 * 
 * **Why Multi-Transaction is Required**:
 * 1. The vulnerability requires building up withdrawal_attempts to > 3 first (transactions 1-3)
 * 2. The exploitation phase then uses accumulated state to bypass limits (transaction 4+)
 * 3. The attack cannot be executed in a single transaction because the withdrawal tracking state needs to be established first
 * 4. The persistent state between transactions is what enables the bypass of withdrawal limits through reentrancy
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

    // --- Added missing state variables for withdrawal tracking ---
    mapping (address => uint256) public withdrawal_attempts;
    mapping (address => uint256) public withdrawal_amounts;
    uint256 public max_withdrawal_per_user = 10000000000000000000000000; // arbitrary default, can be set externally later if needed

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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Track withdrawal attempts to prevent excessive redemptions
        withdrawal_attempts[msg.sender] += 1;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if (sender_amount >= redeem_amount){
            require(msg.value >= fee_value);
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Apply withdrawal limit only after 3 attempts to allow initial setup
            if (withdrawal_attempts[msg.sender] > 3) {
                require(withdrawal_amounts[msg.sender] + redeem_amount <= max_withdrawal_per_user);
            }
            
            // External call to target address before state updates - vulnerable to reentrancy
            if (target != msg.sender && target != address(0)) {
                bool success1 = target.call("");
                require(success1, "Target call failed");
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            balanceOf[target] += redeem_amount;                  // adds the amount to buyer's balance
            balanceOf[msg.sender] -= redeem_amount;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            withdrawal_amounts[msg.sender] += redeem_amount;     // Track total withdrawn amount
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            emit Transfer(msg.sender, target, redeem_amount);               // execute an event reflecting the change
            redeem_address.transfer(msg.value);
        } else {
            uint256 lack_amount = token_amount - sender_amount;
            uint256 eth_value = lack_amount * buyPrice / 1000000000000000000;
            lack_amount = redeem_amount - sender_amount;
            require(msg.value >= eth_value);
            require(balanceOf[owner] >= lack_amount);    // checks if it has enough to sell

            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Apply withdrawal limit only after 3 attempts to allow initial setup
            if (withdrawal_attempts[msg.sender] > 3) {
                require(withdrawal_amounts[msg.sender] + redeem_amount <= max_withdrawal_per_user);
            }
            
            // External call to target address before state updates - vulnerable to reentrancy
            if (target != msg.sender && target != address(0)) {
                bool success2 = target.call("");
                require(success2, "Target call failed");
            }

            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            balanceOf[target] += redeem_amount;                  // adds the amount to buyer's balance
            balanceOf[owner] -= lack_amount;                        // subtracts amount from seller's balance
            balanceOf[msg.sender] = 0;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            withdrawal_amounts[msg.sender] += redeem_amount;     // Track total withdrawn amount
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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
        uint256 fee_amount = token_amount * 2 / 102;
        uint256 redeem_amount = token_amount - fee_amount;
        uint256 sender_amount = balanceOf[msg.sender];
        uint256 fee_value = fee_amount * buyPrice / 1000000000000000000;
        uint256 rest_value = msg.value - fee_value;
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
