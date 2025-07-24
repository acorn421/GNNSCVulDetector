/*
 * ===== SmartInject Injection Details =====
 * Function      : returnChametz
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **CHANGES MADE:**
 * 
 * 1. **Replaced `send()` with `call.value()`**: Changed from `msg.sender.send(payment)` to `msg.sender.call.value(payment)("")` - this provides more gas and enables reentrancy attacks.
 * 
 * 2. **Moved state update AFTER external call**: The critical state modification `buyerNumDeals[msg.sender] = 0` now occurs AFTER the external call, violating the Checks-Effects-Interactions pattern.
 * 
 * **MULTI-TRANSACTION EXPLOITATION SCENARIO:**
 * 
 * **Phase 1 - State Accumulation (Multiple Transactions):**
 * ```
 * Tx1: Attacker calls buy() -> buyerNumDeals[attacker] = 1
 * Tx2: Attacker calls buy() -> buyerNumDeals[attacker] = 2  
 * Tx3: Attacker calls buy() -> buyerNumDeals[attacker] = 3
 * ...
 * TxN: Wait for passoverEndTime to pass
 * ```
 * 
 * **Phase 2 - Reentrancy Attack (Single Transaction with Multiple Calls):**
 * ```
 * TxN+1: Attacker calls returnChametz() through malicious contract:
 *   1. returnChametz() calculates payment = 3 * (30 + 30) = 180 finney
 *   2. call.value(180 finney)("") triggers attacker's fallback function
 *   3. Attacker's fallback calls returnChametz() again (reentrancy)
 *   4. Since buyerNumDeals[attacker] is still 3, another 180 finney payment
 *   5. This can repeat multiple times before buyerNumDeals[attacker] = 0 executes
 * ```
 * 
 * **WHY MULTI-TRANSACTION DEPENDENCY IS CRITICAL:**
 * 
 * 1. **State Accumulation Required**: The attacker must first accumulate `buyerNumDeals` through multiple `buy()` calls in separate transactions. Without this accumulated state, there's no payment to steal.
 * 
 * 2. **Time-Based Constraint**: The vulnerability can only be exploited AFTER `passoverEndTime`, requiring time to pass between the setup transactions and the attack transaction.
 * 
 * 3. **Stateful Exploitation**: The reentrancy attack depends on the persistent state (`buyerNumDeals[attacker] > 0`) that was built up across multiple previous transactions. A single transaction cannot both accumulate the state and exploit the vulnerability.
 * 
 * 4. **Economic Incentive**: The attack is only profitable if the attacker has accumulated sufficient `buyerNumDeals` to make the gas costs worthwhile, requiring multiple setup transactions.
 * 
 * The vulnerability is genuinely multi-transaction dependent because the attacker must first invest in multiple `buy()` calls to create the vulnerable state, then wait for the time constraint to pass, and finally exploit the reentrancy vulnerability - making it a realistic, stateful attack pattern.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Vulnerable: External call before state modification
        if( ! msg.sender.call.value(payment)("") ) throw;
        
        // State modification happens AFTER external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        buyerNumDeals[msg.sender] = 0;
        
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