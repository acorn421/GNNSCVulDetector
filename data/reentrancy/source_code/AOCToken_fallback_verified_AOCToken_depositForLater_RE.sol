/*
 * ===== SmartInject Injection Details =====
 * Function      : depositForLater
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * This injection introduces a stateful, multi-transaction reentrancy vulnerability. The vulnerability requires: 1) First transaction: user calls depositForLater() to deposit ETH, 2) Second transaction: user calls processPendingDeposit() which has a reentrancy vulnerability. The vulnerability occurs because the deposit_claimed flag is set to true and AOC_available is updated before the external AOC.transfer() call, but the pending_deposits mapping is only cleared after the external call. A malicious contract can exploit this by calling processPendingDeposit() during the AOC.transfer() callback, allowing multiple AOC withdrawals while the pending deposit remains non-zero until the original call completes.
 */
pragma solidity ^0.4.19;

// Axie AOC sell contract. Not affiliated with the game developers. Use at your own risk.
// ... [comments omitted for brevity] ...

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

    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    mapping(address => uint256) public pending_deposits;
    mapping(address => bool) public deposit_claimed;
    
    // Allow users to deposit ETH for future AOC purchases with better rates
    function depositForLater() public payable {
        require(msg.value > 0, "Must send ETH to deposit");
        pending_deposits[msg.sender] += msg.value;
        deposit_claimed[msg.sender] = false;
    }
    
    // Process pending deposits to buy AOC - vulnerable to reentrancy
    function processPendingDeposit() public {
        require(pending_deposits[msg.sender] > 0, "No pending deposits");
        require(!deposit_claimed[msg.sender], "Already claimed");
        require(price > 0, "No AOC available for sale");
        
        uint256 deposit_amount = pending_deposits[msg.sender];
        uint256 AOC_balance = AOC.balanceOf(this);
        uint256 num_AOC = deposit_amount / price;
        
        require(AOC_balance >= num_AOC, "Insufficient AOC in contract");
        
        // State change happens before external call - vulnerable to reentrancy
        deposit_claimed[msg.sender] = true;
        AOC_available = AOC_balance - num_AOC;
        
        // External call to transfer AOC - reentrancy point
        require(AOC.transfer(msg.sender, num_AOC));
        
        // State change after external call - vulnerable
        pending_deposits[msg.sender] = 0;
        
        // ETH transfer happens last - if reentrancy occurs, ETH won't be transferred
        // but deposit_claimed flag was already set to true
        if (deposit_amount > 0) {
            msg.sender.transfer(deposit_amount);
        }
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
