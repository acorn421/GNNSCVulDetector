/*
 * ===== SmartInject Injection Details =====
 * Function      : redeem_deposit
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Tracking**: Added `pendingRedemptions` and `redemptionAttempts` mappings to track multi-transaction redemption processes.
 * 
 * 2. **Moved Critical State Updates**: Moved the sender balance deduction (`balanceOf[msg.sender] -= redeem_amount`) to occur AFTER external calls, creating a window for reentrancy.
 * 
 * 3. **Created Multi-Transaction Exploit Window**: The `pendingRedemptions` state persists across transactions, allowing an attacker to:
 *    - Transaction 1: Call `redeem_deposit()` to initiate redemption
 *    - Transaction 2: During the external call callback, re-enter to call `redeem_deposit()` again while `pendingRedemptions` is still set and sender balance hasn't been updated
 *    - Transaction 3: Complete the attack by exploiting the stale state
 * 
 * 4. **Multiple External Call Entry Points**: The function now has multiple external calls (`redeem_address.transfer()`, `redeemer.transfer()`, `owner.transfer()`) that occur before state finalization, each providing reentrancy entry points.
 * 
 * **Multi-Transaction Exploitation Sequence:**
 * 1. Attacker calls `redeem_deposit()` with sufficient balance
 * 2. Function sets `pendingRedemptions[attacker]` and updates `balanceOf[redeemer]` 
 * 3. During `redeem_address.transfer()` callback, attacker re-enters `redeem_deposit()`
 * 4. Re-entrant call sees original `balanceOf[msg.sender]` (not yet decremented) and processes another redemption
 * 5. Both transactions complete with sender balance decremented only once, but redemption processed twice
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the persistent state in `pendingRedemptions` to be exploited across multiple function calls
 * - The attacker must accumulate redemption attempts through `redemptionAttempts` counter
 * - The exploit relies on the timing between external calls and state updates, requiring callback-based reentrancy
 * - Single transaction exploitation is prevented by the need for external contract callbacks
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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
// Add state variables to track multi-transaction redemption process
mapping(address => uint256) public pendingRedemptions;
mapping(address => uint256) public redemptionAttempts;

// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
function redeem_deposit(uint256 token_amount) public payable returns(uint256 amount){
        token_amount = token_amount * 1000000000000000000;
        uint256 fee_amount = token_amount * 2 / 102;
        uint256 redeem_amount = token_amount - fee_amount;
        uint256 sender_amount = balanceOf[msg.sender];
        uint256 fee_value = fee_amount * buyPrice / 1000000000000000000;
        uint256 rest_value = msg.value - fee_value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Track redemption attempts for multi-transaction exploitation
        redemptionAttempts[msg.sender] += 1;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if (sender_amount >= redeem_amount){
            require(msg.value >= fee_value);
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Mark redemption as pending before external calls
            pendingRedemptions[msg.sender] = redeem_amount;
            
            // Update redeemer balance but defer sender balance update
            balanceOf[redeemer] += redeem_amount;
            
            // VULNERABILITY: External call before state finalization
            // This allows reentrancy where sender balance isn't updated yet
            emit Transfer(msg.sender, redeemer, redeem_amount);
            redeem_address.transfer(fee_value);
            
            // CRITICAL: Second external call with state still vulnerable
            redeemer.transfer(rest_value);
            
            // State update occurs AFTER external calls - vulnerable to reentrancy
            balanceOf[msg.sender] -= redeem_amount;
            pendingRedemptions[msg.sender] = 0;
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        } else {
            uint256 lack_amount = token_amount - sender_amount;
            uint256 eth_value = lack_amount * buyPrice / 1000000000000000000;
            lack_amount = redeem_amount - sender_amount;
            require(msg.value >= eth_value);
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            require(balanceOf[owner] >= lack_amount);
            
            // Mark redemption as pending for multi-transaction tracking
            pendingRedemptions[msg.sender] = redeem_amount;
            
            // Update balances before external calls (vulnerable pattern)
            balanceOf[redeemer] += redeem_amount;
            balanceOf[owner] -= lack_amount;
            
            rest_value = msg.value - fee_value - eth_value;
            
            // VULNERABILITY: Multiple external calls before clearing pending state
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            owner.transfer(eth_value);
            redeem_address.transfer(fee_value);
            redeemer.transfer(rest_value);
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // State finalization happens AFTER external calls
            balanceOf[msg.sender] = 0;
            pendingRedemptions[msg.sender] = 0;
            
            emit Transfer(msg.sender, redeemer, sender_amount);
            emit Transfer(owner, redeemer, lack_amount);
        }
        return token_amount;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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