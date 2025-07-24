/*
 * ===== SmartInject Injection Details =====
 * Function      : returnChametz
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability that requires multiple function calls over time to exploit effectively. The vulnerability includes:
 * 
 * 1. **Time-Based Bonus Accumulation**: Added `firstReturnTimestamp` state variable that gets set on the first call to `returnChametz` by any user. Subsequent calls by any user can benefit from increasing time bonuses based on how much time has passed since the first return.
 * 
 * 2. **Per-User Timestamp Tracking**: Added `lastReturnTimestamp[msg.sender]` mapping to track when each user last called the function, enabling future temporal-based calculations.
 * 
 * 3. **Block Hash Dependency**: Added block hash-based bonus calculation using `block.blockhash(block.number - 1)` which creates dependency on specific block properties.
 * 
 * **Multi-Transaction Exploitation Scenarios:**
 * 
 * 1. **Temporal Bonus Gaming**: 
 *    - Transaction 1: First user calls `returnChametz` to set `firstReturnTimestamp`
 *    - Transaction 2+: Other users wait for optimal time periods (multiples of 256 blocks) to maximize their `timeBonus`
 *    - Miners can manipulate timestamps across multiple blocks to accelerate bonus accumulation
 * 
 * 2. **Block Hash Manipulation**:
 *    - Users can monitor block hashes and only call the function when `block.blockhash(block.number - 1) % 100 < 10` is true
 *    - Miners can influence block hashes across multiple blocks to create favorable conditions
 *    - Requires monitoring multiple blocks and timing transactions accordingly
 * 
 * 3. **Coordinated Timing Attacks**:
 *    - Users can coordinate to ensure the first caller sets `firstReturnTimestamp` at an optimal time
 *    - Subsequent callers can time their transactions to benefit from maximum accumulated bonuses
 *    - Requires multiple participants across multiple transactions
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * 
 * 1. **State Accumulation**: The `timeBonus` only increases over time after `firstReturnTimestamp` is set, requiring the passage of real time and multiple blocks
 * 2. **Block Hash Dependency**: Users need to observe multiple blocks to find favorable block hash conditions
 * 3. **Temporal Coordination**: Maximum exploitation requires coordination between multiple users across multiple transactions
 * 4. **Time-Based Rewards**: The bonus structure inherently requires time passage between transactions to be maximally effective
 * 
 * This vulnerability cannot be exploited in a single transaction because it depends on:
 * - Time passage between the first return and subsequent returns
 * - Block hash values that change between blocks
 * - State accumulation that builds up over multiple function calls
 * - Temporal patterns that only emerge across multiple transactions
 */
pragma solidity ^0.4.9;

contract SaleOfChametz {
    struct Deal {
        address seller;
    }
    
    Deal[] public deals;
    uint   public nextDealIndex;
    
    mapping(address=>uint) public sellerNumOpenDeals;
    mapping(address=>uint) public buyerNumDeals;

    // Added missing state variables required for returnChametz vulnerability logic
    uint public firstReturnTimestamp;
    mapping(address => uint) public lastReturnTimestamp;
    
    event Sell( address indexed seller, uint timestamp );
    event Buy( address indexed buyer, address indexed seller, uint timestamp );
    event ReturnChametz( address indexed buyer, uint payment, uint timestamp );
    event CancelSell( address indexed seller, uint payment, uint timestamp );
    
    uint constant public passoverStartTime = 1491840000;
    uint constant public passoverEndTime = 1492401600;                                        
    
    uint constant public downPayment = 30 finney;
    uint constant public buyerBonus = 30 finney;
    
    function SaleOfChametz() public {}
    
    function numChametzForSale() public constant returns(uint) {
        return deals.length - nextDealIndex;
    }
    
    function sell() public payable {
        if( now >= passoverStartTime ) throw; // too late to sell
        if( msg.value != buyerBonus ) throw;
        
        Deal memory deal;
        deal.seller = msg.sender;
        
        sellerNumOpenDeals[ msg.sender ]++;
        
        deals.push(deal);
        
        Sell( msg.sender, now );
    }
    
    function buy() public payable {
        if( now >= passoverStartTime ) throw; // too late to buy
        if( msg.value != downPayment ) throw;
        if( deals.length <= nextDealIndex ) throw; // no deals
        
        Deal memory deal = deals[nextDealIndex];
        if( sellerNumOpenDeals[ deal.seller ] > 0 ) {
            sellerNumOpenDeals[ deal.seller ]--;
        }
        
        buyerNumDeals[msg.sender]++;
        nextDealIndex++;
        
        Buy( msg.sender, deal.seller, now );
    }
    
    function returnChametz() public {
        if( now <= passoverEndTime ) throw; // too early to return
        if( buyerNumDeals[msg.sender] == 0 ) throw; // never bought chametz
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Store the first return timestamp for bonus calculation
        if( firstReturnTimestamp == 0 ) {
            firstReturnTimestamp = now;
        }
        
        // Calculate time-based bonus that accumulates over multiple calls
        uint timeBonus = 0;
        if( now > firstReturnTimestamp ) {
            uint timeDiff = now - firstReturnTimestamp;
            // Bonus increases every 256 blocks (approximately 1 hour)
            timeBonus = (timeDiff / 256) * (downPayment / 10);
        }
        
        // Store caller's return timestamp for future bonus calculations
        lastReturnTimestamp[msg.sender] = now;
        
        // Use block hash for additional "randomness" in bonus calculation
        uint blockBonus = 0;
        if( uint(block.blockhash(block.number - 1)) % 100 < 10 ) {
            blockBonus = buyerBonus / 2;
        }
        
        uint payment = buyerNumDeals[msg.sender] * (downPayment + buyerBonus + timeBonus + blockBonus);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        buyerNumDeals[msg.sender] = 0;
        if( ! msg.sender.send( payment ) ) throw;
        
        ReturnChametz( msg.sender, payment, now );
    }
    
    function cancelSell() public {
       if( now <= passoverStartTime ) throw; // too early to cancel
        
        if( sellerNumOpenDeals[ msg.sender ] == 0 ) throw; // no deals to cancel
        uint payment = sellerNumOpenDeals[ msg.sender ] * buyerBonus;
        sellerNumOpenDeals[ msg.sender ] = 0;
        if( ! msg.sender.send( payment ) ) throw;
        
        CancelSell( msg.sender, payment, now );
    }
    
}
