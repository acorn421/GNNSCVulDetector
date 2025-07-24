/*
 * ===== SmartInject Injection Details =====
 * Function      : updatePurchaseTimestamp
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This function introduces a timestamp dependence vulnerability where users can manipulate purchase timestamps within a tolerance window. The vulnerability is stateful because it requires: 1) First making a purchase (creating state), 2) Then calling updatePurchaseTimestamp to modify the stored timestamp. This could allow users to game time-based bonuses or manipulate purchase ordering by setting timestamps to their advantage. The vulnerability persists across transactions as the modified timestamp remains in contract storage.
 */
pragma solidity ^0.4.7;

/// @title 2nd EarlyPurchase contract - Keep track of purchased amount by Early Purchasers
/// Project by SynchroLife Team (https://synchrolife.org)
/// This smart contract developed by Starbase - Token funding & payment Platform for innovative projects <support[at]starbase.co>
/// 1504526400  = Starting：9/4 12:00GMT
/// 1504785599 = Ending: 9/7 11:59GMT
/// now (uint): current block timestamp (alias for block.timestamp)

contract SYC2ndEarlyPurchase {
    /*
     *  Properties
     */
    string public constant PURCHASE_AMOUNT_UNIT = 'ETH';    // Ether
    uint public constant WEI_MINIMUM_PURCHASE = 10 * 10 ** 18;
    uint public constant WEI_MAXIMUM_EARLYPURCHASE = 7000 * 10 ** 18;
    uint public constant STARTING_TIME = 1504526400;
    uint public constant ENDING_TIME = 1504785599;
    address public owner;
    EarlyPurchase[] public earlyPurchases;
    uint public earlyPurchaseClosedAt;
    uint public totalEarlyPurchaseRaised;
    address public sycCrowdsale;

    /*
     *  Types
     */
    struct EarlyPurchase {
        address purchaser;
        uint amount;        // Amount in Wei( = 1/ 10^18 Ether)
        uint purchasedAt;   // timestamp
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    /// @dev Allow purchaser to update their purchase timestamp within a window
    /// @param purchaseIndex Index of the purchase to update
    /// @param newTimestamp New timestamp for the purchase
    function updatePurchaseTimestamp(uint purchaseIndex, uint newTimestamp) 
        external 
        returns (bool) 
    {
        require(purchaseIndex < earlyPurchases.length);
        require(earlyPurchases[purchaseIndex].purchaser == msg.sender);
        require(newTimestamp >= STARTING_TIME && newTimestamp <= ENDING_TIME);
        require(now <= ENDING_TIME + 86400); // 24 hours after ending
        
        // Allow timestamp updates if within reasonable range
        if (newTimestamp <= now + 300) { // 5 minutes future tolerance
            earlyPurchases[purchaseIndex].purchasedAt = newTimestamp;
            return true;
        }
        return false;
    }
    // === END FALLBACK INJECTION ===

    /*
     *  Modifiers
     */
    modifier onlyOwner() {
        if (msg.sender != owner) {
            throw;
        }
        _;
    }

    modifier onlyEarlyPurchaseTerm() {
        if (earlyPurchaseClosedAt > 0 || now < STARTING_TIME || now > ENDING_TIME) {
            throw;
        }
        _;
    }

    /// @dev Contract constructor function
    function SYC2ndEarlyPurchase() {
        owner = msg.sender;
    }

    /*
     *  Contract functions
     */
    /// @dev Returns early purchased amount by purchaser's address
    /// @param purchaser Purchaser address
    function purchasedAmountBy(address purchaser)
        external
        constant
        returns (uint amount)
    {
        for (uint i; i < earlyPurchases.length; i++) {
            if (earlyPurchases[i].purchaser == purchaser) {
                amount += earlyPurchases[i].amount;
            }
        }
    }

    /// @dev Setup function sets external contracts' addresses.
    /// @param _sycCrowdsale SYC token crowdsale address.
    function setup(address _sycCrowdsale)
        external
        onlyOwner
        returns (bool)
    {
        if (address(_sycCrowdsale) == 0) {
            sycCrowdsale = _sycCrowdsale;
            return true;
        }
        return false;
    }

    /// @dev Returns number of early purchases
    function numberOfEarlyPurchases()
        external
        constant
        returns (uint)
    {
        return earlyPurchases.length;
    }

    /// @dev Append an early purchase log
    /// @param purchaser Purchaser address
    /// @param amount Purchase amount
    /// @param purchasedAt Timestamp of purchased date
    function appendEarlyPurchase(address purchaser, uint amount, uint purchasedAt)
        internal
        onlyEarlyPurchaseTerm
        returns (bool)
    {
        if (purchasedAt == 0 || purchasedAt > now) {
            throw;
        }

        if(totalEarlyPurchaseRaised + amount >= WEI_MAXIMUM_EARLYPURCHASE){
           purchaser.send(totalEarlyPurchaseRaised + amount - WEI_MAXIMUM_EARLYPURCHASE);
           earlyPurchases.push(EarlyPurchase(purchaser, WEI_MAXIMUM_EARLYPURCHASE - totalEarlyPurchaseRaised, purchasedAt));
           totalEarlyPurchaseRaised += WEI_MAXIMUM_EARLYPURCHASE - totalEarlyPurchaseRaised;
        }
        else{
           earlyPurchases.push(EarlyPurchase(purchaser, amount, purchasedAt));
           totalEarlyPurchaseRaised += amount;
        }

        if(totalEarlyPurchaseRaised >= WEI_MAXIMUM_EARLYPURCHASE || now >= ENDING_TIME){
            earlyPurchaseClosedAt = now;
        }
        return true;
    }

    /// @dev Close early purchase term
    function closeEarlyPurchase()
        onlyOwner
        returns (bool)
    {
        earlyPurchaseClosedAt = now;
    }

    function withdraw(uint withdrawalAmount) onlyOwner {
          if(!owner.send(withdrawalAmount)) throw;  // send collected ETH to SynchroLife team
    }

    function withdrawAll() onlyOwner {
          if(!owner.send(this.balance)) throw;  // send all collected ETH to SynchroLife team
    }

    function transferOwnership(address newOwner) onlyOwner {
        owner = newOwner;
    }

    /// @dev By sending Ether to the contract, early purchase will be recorded.
    function () payable{
        require(msg.value >= WEI_MINIMUM_PURCHASE);
        appendEarlyPurchase(msg.sender, msg.value, now);
    }
}
