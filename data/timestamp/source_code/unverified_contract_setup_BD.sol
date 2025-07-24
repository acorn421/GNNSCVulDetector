/*
 * ===== SmartInject Injection Details =====
 * Function      : setup
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced multiple timestamp dependencies that create a stateful, multi-transaction vulnerability:
 * 
 * 1. **Time-based Price Decay**: Added logic that calculates price adjustments based on block.timestamp, causing the price to decrease over time. However, the calculation references setup_timestamp which is a local variable, making it always 0 in subsequent calls, creating inconsistent pricing behavior.
 * 
 * 2. **Timestamp-dependent Availability**: Used block.timestamp in a modulo operation to determine AOC_available, making token availability dependent on when the transaction is mined. This creates unpredictable behavior across different blocks.
 * 
 * 3. **Pseudo-random Time Seed**: Combined block.timestamp and block.number to create a "random" seed that affects AOC availability, making the contract behavior dependent on mining timing.
 * 
 * **Multi-Transaction Exploitation**:
 * - Transaction 1: Attacker calls setup() and observes the timestamp-dependent state changes
 * - Transaction 2: Attacker waits for favorable block timing and calls the fallback function to purchase tokens at manipulated prices
 * - Transaction 3+: Attacker can repeat purchases as the timestamp-dependent logic creates different availability and pricing on each block
 * 
 * **Stateful Nature**: The vulnerability persists across transactions because the timestamp-dependent calculations modify persistent state variables (price, AOC_available) that affect all subsequent trading operations through the fallback function.
 * 
 * **Realistic Vulnerability**: The code appears to implement "dynamic pricing" and "time-based availability" features but does so using unreliable block properties, creating exploitable timing dependencies that miners or sophisticated attackers can manipulate.
 */
pragma solidity ^0.4.19;

// Axie AOC sell contract. Not affiliated with the game developers. Use at your own risk.
//
// BUYERS: to protect against scams:
// 1) check the price by clicking on "Read smart contract" in etherscan. Two prices are published
//     a) price for 1 AOC in wei (1 wei = 10^-18 ETH), and b) number of AOC you get for 1 ETH
// 2) Make sure you use high enough gas price that your TX confirms within 1 hour, to avoid the scam
//    detailed below*
// 3) Check the hardcoded AOC address below givet to AOCToken() constructor. Make sure this is the real AOC
//    token. Scammers could clone this contract and modify the address to sell you fake tokens.
//

// This contract enables trustless exchange of AOC tokens for ETH.
// Anyone can use this contract to sell AOC, as long as it is in an empty state.
// Contract is in an empty state if it has no AOC or ETH in it and is not in cooldown
// The main idea behind the contract is to keep it very simple to use, especially for buyers.
// Sellers need to set allowance and call the setup() function using MEW, which is a little more involved.
// Buyers can use Metamask to send and receive AOC tokens.
//
// To use the contract:
// 1) Call approve on the AOC ERC20 address for this contract. That will allow the contract
//    to hold your AOC tokens in escrow. You can always withdraw you AOC tokens back.
//    You can make this call using MEW. The AOC contract address and ABI are available here:
//    https://etherscan.io/address/0x73d7b530d181ef957525c6fbe2ab8f28bf4f81cf#code
// 2) Call setup(AOC_amount, price) on this contract, for example by using MEW.
//    This call will take your tokens and hold them in escrow, while at the same time
//    you get the ownership of the contract. While you own the contract (i.e. while the contract
//    holds your tokens or your ETH, nobody else can call setup(). If they do, the call will fail.
//    If you call approve() on the AOC contract, but someone else calls setup() on this contract
//    nothing bad happens. You can either wait for this contract to go into empty state, or find
//    another contract (or publish your own). You will need to call approve() again for the new contract.
// 3) Advertise the contract address so others can buy AOC from it. Buying AOC is simple, the
//    buyer needs to send ETH to the contract address, and the contract sends them AOC. The buyer
//    can verify the price by viewing the contract.
// 4) To claim your funds back (both AOC and ETH resulting from any sales), simply send 0 ETH to
//    the contract. The contract will send you ETH and AOC back, and reset the contract for others to use.
//
// *) There is a cooldown period of 1 hour after the contract is reset, before it can be used again.
//    This is to avoid possible scams where the seller sees a pending TX on the contract, then resets
//    the contract and call setup() is a much higher price. If the seller does that with very high gas price,
//    they could change the price for the buyer's pending TX. A cooldown of 1 hour prevents this attac, as long
//    as the buyer's TX confirms within the hour.


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
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Store setup timestamp for time-based pricing adjustments
        uint256 setup_timestamp = block.timestamp;
        
        // Time-based price adjustment: price decreases by 1% every hour after setup
        uint256 time_adjusted_price = price_in_wei;
        if (setup_timestamp > 0) {
            uint256 hours_passed = (block.timestamp - setup_timestamp) / 3600;
            if (hours_passed > 0) {
                // Price decays by 1% per hour, minimum 50% of original price
                uint256 decay_factor = 100 - (hours_passed > 50 ? 50 : hours_passed);
                time_adjusted_price = (price_in_wei * decay_factor) / 100;
            }
        }
        
        price = time_adjusted_price;
        AOC_available = AOC_amount;
        Amount_of_AOC_for_One_ETH = 1 ether / time_adjusted_price;
        seller = msg.sender;
        
        // Store the setup time in a pseudo-random manner using block properties
        // This creates timestamp dependence that affects future transactions
        uint256 time_seed = uint256(keccak256(abi.encodePacked(block.timestamp, block.number))) % 1000;
        if (time_seed > 500) {
            // Implement time-locked availability - AOC becomes available gradually
            AOC_available = (block.timestamp % 2 == 0) ? AOC_amount : AOC_amount / 2;
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

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