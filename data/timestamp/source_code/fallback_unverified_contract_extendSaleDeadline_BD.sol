/*
 * ===== SmartInject Injection Details =====
 * Function      : extendSaleDeadline
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
 * This vulnerability introduces a timestamp dependence issue where the contract relies on block.timestamp (now) for critical timing decisions in a multi-transaction sequence. An attacker must first call requestDeadlineExtension() to set their timestamp, wait for the time requirement, then call extendSaleDeadline() during a specific window. Miners can manipulate timestamps within ~15 seconds, potentially allowing sellers to extend deadlines when they shouldn't be able to, or bypass the 5-minute waiting period. The vulnerability requires multiple transactions and persisted state (extensionRequestTimestamp and hasRequestedExtension mappings) to exploit.
 */
pragma solidity ^0.4.9;

contract SaleOfChametz {
    struct Deal {
        address seller;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    uint public saleDeadlineExtension = 0;
    mapping(address=>uint) public extensionRequestTimestamp;
    mapping(address=>bool) public hasRequestedExtension;
    
    function requestDeadlineExtension() {
        if( sellerNumOpenDeals[msg.sender] == 0 ) throw; // must have open deals
        if( hasRequestedExtension[msg.sender] ) throw; // already requested
        
        extensionRequestTimestamp[msg.sender] = now;
        hasRequestedExtension[msg.sender] = true;
    }
    
    function extendSaleDeadline() {
        if( !hasRequestedExtension[msg.sender] ) throw; // must request first
        if( sellerNumOpenDeals[msg.sender] == 0 ) throw; // must have open deals
        
        // Vulnerable: relies on block timestamp for critical timing decision
        // Miners can manipulate timestamp within ~15 second window
        uint timeSinceRequest = now - extensionRequestTimestamp[msg.sender];
        if( timeSinceRequest < 300 ) throw; // must wait 5 minutes between request and extension
        
        // Allow extension if requested during vulnerable time window
        if( now >= passoverStartTime - 3600 && now < passoverStartTime ) {
            saleDeadlineExtension = 1800; // extend by 30 minutes
        }
        
        hasRequestedExtension[msg.sender] = false;
    }
    // === END FALLBACK INJECTION ===

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
        if( sellerNumOpenDeals[ deal.seller ] > 0 ) {
            sellerNumOpenDeals[ deal.seller ]--;
        }
        
        buyerNumDeals[msg.sender]++;
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
