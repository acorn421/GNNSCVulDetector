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
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the buyer's contract before state updates. This creates a callback mechanism that allows attackers to re-enter the function during the purchase process.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `msg.sender` using `call()` with a callback function signature `onTokenPurchase(uint256)`
 * 2. The external call is made BEFORE the critical state updates (balance modifications)
 * 3. Added a check for contract code length to ensure the call is only made to contracts
 * 4. The external call occurs after the initial balance check but before state changes
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Setup Transaction**: Attacker deploys a malicious contract that implements `onTokenPurchase()` callback
 * 2. **First Attack Transaction**: Attacker's contract calls `buy()` with sufficient ETH
 *    - The function calculates the token amount
 *    - Checks if owner has enough tokens (passes initially)
 *    - Makes external call to attacker's `onTokenPurchase()` callback
 *    - **Reentrancy Point**: In the callback, attacker calls `buy()` again
 *    - The reentrant call sees the same initial state (owner's balance not yet decremented)
 *    - Multiple reentrant calls can pass the balance check since owner's balance hasn't been updated yet
 * 3. **State Accumulation**: Each reentrant call adds tokens to attacker's balance without properly decrementing owner's balance
 * 4. **Result**: Attacker receives more tokens than the owner actually had available
 * 
 * **Why Multi-Transaction is Required:**
 * - **State Persistence**: The vulnerability relies on the persistent state of `balanceOf` mappings across function calls
 * - **Accumulated Effect**: Each reentrant call accumulates tokens in the attacker's balance
 * - **Sequential Dependency**: The exploit requires a sequence of calls where the external callback enables additional function calls before state updates complete
 * - **Cross-Call State Manipulation**: The vulnerability is only effective when state changes from multiple calls interact with each other
 * 
 * This creates a realistic reentrancy vulnerability commonly seen in DeFi protocols where callback mechanisms are used for user notifications but implemented unsafely.
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

    function Athleticoin() public {
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

        // External call to buyer's contract before state updates - vulnerable to reentrancy
        uint256 size;
        assembly { size := extcodesize(callvalue()) }
        address buyer = msg.sender;
        assembly { size := extcodesize(buyer) }
        if (size > 0) {
            if (!msg.sender.call(bytes4(sha3("onTokenPurchase(uint256)")), amount)) {
                revert();
            }
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
