/*
 * ===== SmartInject Injection Details =====
 * Function      : reserveTokens
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This injection adds a token reservation system that suffers from timestamp dependence vulnerability. The vulnerability is stateful and requires multiple transactions: (1) reserveTokens() to create a reservation with a timestamp, (2) claimReservedTokens() to claim within the time window. Miners can manipulate block.timestamp within reasonable bounds (up to 15 seconds in the future), potentially causing legitimate users to lose their reservations or allowing malicious actors to extend their reservation windows. The vulnerability persists across multiple blocks and requires state changes between transactions.
 */
pragma solidity ^0.4.19;

// Axie AOC sell contract. Not affiliated with the game developers. Use at your own risk.
// ... (comments omitted for brevity)

interface AOCToken {
    function balanceOf(address who) external view returns (uint256);
    function transfer(address to, uint256 value) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

contract AOCTrader {
    AOCToken AOC = AOCToken(0x73d7B530d181ef957525c6FBE2Ab8F28Bf4f81Cf); // hardcoded AOC address to avoid scams.
    address public seller;
    uint256 public price; // price is in wei, not ether
    uint256 public AOC_available; // remaining amount of AOC. This is just a convenience variable for buyers, not really used in the contract.
    uint256 public Amount_of_AOC_for_One_ETH; // shows how much AOC you get for 1 ETH. Helps avoid price scams.
    uint256 cooldown_start_time;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // These variables must be declared outside the constructor
    uint256 public reservation_timestamp;
    address public reserver;
    uint256 public reserved_amount;
    
    // Allows users to reserve tokens for a specific time window
    function reserveTokens(uint256 amount) public payable {
        require(msg.value > 0, "Must send ETH to reserve tokens");
        require(amount > 0, "Amount must be greater than 0");
        require(AOC.balanceOf(this) >= amount, "Not enough tokens available");
        require(reserver == 0x0, "Tokens already reserved");
        
        // Vulnerable: Using block.timestamp for time-sensitive operations
        // Miners can manipulate timestamp within reasonable bounds
        reservation_timestamp = block.timestamp;
        reserver = msg.sender;
        reserved_amount = amount;
    }
    
    // Allows the reserver to claim their reserved tokens within time window
    function claimReservedTokens() public {
        require(msg.sender == reserver, "Only reserver can claim");
        require(reserved_amount > 0, "No tokens reserved");
        
        // Vulnerable: Timestamp dependence - miners can manipulate block.timestamp
        // This creates a multi-transaction vulnerability where:
        // 1. User calls reserveTokens() (first transaction)
        // 2. Malicious miner manipulates timestamp in subsequent blocks
        // 3. User's claimReservedTokens() call (second transaction) may fail or succeed based on manipulated time
        require(block.timestamp <= reservation_timestamp + 1800, "Reservation expired"); // 30 minutes window
        
        uint256 amount = reserved_amount;
        
        // Reset state
        reservation_timestamp = 0;
        reserver = 0x0;
        reserved_amount = 0;
        
        // Refund ETH and transfer reserved tokens
        msg.sender.transfer(this.balance);
        require(AOC.transfer(msg.sender, amount));
    }
    // === END FALLBACK INJECTION ===

    function AOCTrader() public {
        seller = 0x0;
        price = 0;
        AOC_available = 0;
        Amount_of_AOC_for_One_ETH = 0;
        cooldown_start_time = 0;
    }

    // convenience is_empty function. Sellers should check this before using the contract
    function is_empty() public view returns (bool) {
        return (now - cooldown_start_time > 1 hours) && (this.balance==0) && (AOC.balanceOf(this) == 0);
    }
    
    // Before calling setup, the sender must call Approve() on the AOC token 
    // That sets allowance for this contract to sell the tokens on sender's behalf
    function setup(uint256 AOC_amount, uint256 price_in_wei) public {
        require(is_empty()); // must not be in cooldown
        require(AOC.allowance(msg.sender, this) >= AOC_amount); // contract needs enough allowance
        require(price_in_wei > 1000); // to avoid mistakes, require price to be more than 1000 wei
        
        price = price_in_wei;
        AOC_available = AOC_amount;
        Amount_of_AOC_for_One_ETH = 1 ether / price_in_wei;
        seller = msg.sender;

        require(AOC.transferFrom(msg.sender, this, AOC_amount)); // move AOC to this contract to hold in escrow
    }

    function() public payable{
        uint256 eth_balance = this.balance;
        uint256 AOC_balance = AOC.balanceOf(this);
        if(msg.sender == seller){
            seller = 0x0; // reset seller
            price = 0; // reset price
            AOC_available = 0; // reset available AOC
            Amount_of_AOC_for_One_ETH = 0; // reset price
            cooldown_start_time = now; // start cooldown timer

            if(eth_balance > 0) msg.sender.transfer(eth_balance); // withdraw all ETH
            if(AOC_balance > 0) require(AOC.transfer(msg.sender, AOC_balance)); // withdraw all AOC
        }        
        else{
            require(msg.value > 0); // must send some ETH to buy AOC
            require(price > 0); // cannot divide by zero
            uint256 num_AOC = msg.value / price; // calculate number of AOC tokens for the ETH amount sent
            require(AOC_balance >= num_AOC); // must have enough AOC in the contract
            AOC_available = AOC_balance - num_AOC; // recalculate available AOC

            require(AOC.transfer(msg.sender, num_AOC)); // send AOC to buyer
        }
    }
}
