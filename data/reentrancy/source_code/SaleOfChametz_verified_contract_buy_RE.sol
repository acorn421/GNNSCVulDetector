/*
 * ===== SmartInject Injection Details =====
 * Function      : buy
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added external call in vulnerable position**: Inserted a call to the seller's contract using `deal.seller.call.value(0)()` to notify about the purchase, positioned strategically after partial state updates but before completion.
 * 
 * 2. **Created state inconsistency window**: The function now updates `buyerNumDeals[msg.sender]++` first, then makes an external call, then completes remaining state updates (`sellerNumOpenDeals` decrement and `nextDealIndex` increment). This creates a window where the contract state is inconsistent.
 * 
 * 3. **Multi-transaction exploitation path**:
 *    - **Transaction 1**: Attacker calls `buy()` with a malicious seller contract
 *    - **During external call**: The seller's contract receives the notification and can re-enter `buy()` 
 *    - **State inconsistency**: At this point, `buyerNumDeals` is incremented but `nextDealIndex` hasn't been updated yet
 *    - **Transaction 2 (Reentrancy)**: The malicious seller can call `buy()` again, potentially buying the same deal multiple times or manipulating the deal queue
 *    - **Transaction 3+**: Additional reentrancy calls can accumulate state changes
 * 
 * 4. **Stateful vulnerability**: The vulnerability relies on the accumulated state from `buyerNumDeals` increments across multiple calls, while `nextDealIndex` remains unchanged during the reentrancy window. This allows manipulation of the deal purchasing system across multiple transactions.
 * 
 * 5. **Realistic integration**: The notification mechanism is a common pattern in marketplace contracts where sellers need to be informed of purchases, making this vulnerability realistic and subtle.
 * 
 * The vulnerability requires multiple transactions because the attacker needs to:
 * - Set up a malicious seller contract (Transaction 1)
 * - Trigger the initial `buy()` call (Transaction 2) 
 * - Exploit the reentrancy during the notification callback (Transaction 3+)
 * - Accumulate state changes across these multiple calls to achieve exploitation
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
    
    
    event Sell( address indexed seller, uint timestamp );
    event Buy( address indexed buyer, address indexed seller, uint timestamp );
    event ReturnChametz( address indexed buyer, uint payment, uint timestamp );
    event CancelSell( address indexed seller, uint payment, uint timestamp );
    
    
    uint constant public passoverStartTime = 1491840000;
    uint constant public passoverEndTime = 1492401600;                                        
    
    uint constant public downPayment = 30 finney;
    uint constant public buyerBonus = 30 finney;
    
    function SaleOfChametz() {}
    
    function numChametzForSale() constant returns(uint) {
        return deals.length - nextDealIndex;
    }
    
    function sell() payable {
        if( now >= passoverStartTime ) throw; // too late to sell
        if( msg.value != buyerBonus ) throw;
        
        Deal memory deal;
        deal.seller = msg.sender;
        
        sellerNumOpenDeals[ msg.sender ]++;
        
        deals.push(deal);
        
        Sell( msg.sender, now );
    }
    
    function buy() payable {
        if( now >= passoverStartTime ) throw; // too late to buy
        if( msg.value != downPayment ) throw;
        if( deals.length <= nextDealIndex ) throw; // no deals
        
        Deal memory deal = deals[nextDealIndex];
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update buyer's deal count first (creates vulnerability window)
        buyerNumDeals[msg.sender]++;
        
        // Notify seller about the purchase - EXTERNAL CALL before state completion
        // This allows reentrancy during state inconsistency
        if( deal.seller.call.value(0)(bytes4(keccak256("onPurchaseNotification(address,uint256)")), msg.sender, nextDealIndex) ) {
            // External call successful - continue with state updates
        }
        
        // Complete remaining state updates AFTER external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if( sellerNumOpenDeals[ deal.seller ] > 0 ) {
            sellerNumOpenDeals[ deal.seller ]--;
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        
        nextDealIndex++;
        
        Buy( msg.sender, deal.seller, now );
    }
    
    function returnChametz() {
        if( now <= passoverEndTime ) throw; // too early to return
        if( buyerNumDeals[msg.sender] == 0 ) throw; // never bought chametz
        uint payment = buyerNumDeals[msg.sender] * (downPayment + buyerBonus);
        buyerNumDeals[msg.sender] = 0;
        if( ! msg.sender.send( payment ) ) throw;
        
        ReturnChametz( msg.sender, payment, now );
    }
    
    function cancelSell() {
       if( now <= passoverStartTime ) throw; // too early to cancel
     
        if( sellerNumOpenDeals[ msg.sender ] == 0 ) throw; // no deals to cancel
        uint payment = sellerNumOpenDeals[ msg.sender ] * buyerBonus;
        sellerNumOpenDeals[ msg.sender ] = 0;
        if( ! msg.sender.send( payment ) ) throw;
        
        CancelSell( msg.sender, payment, now );
    }
    
}