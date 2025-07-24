/*
 * ===== SmartInject Injection Details =====
 * Function      : withdraw
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Injected a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added persistent state tracking**: Introduced `pendingWithdrawals` mapping and `totalPendingWithdrawals` to track withdrawal state across transactions
 * 
 * 2. **Violated Checks-Effects-Interactions pattern**: State updates occur both before AND after the external call, creating a window for reentrancy exploitation
 * 
 * 3. **Multi-transaction exploitation mechanism**: 
 *    - **Transaction 1**: Owner calls withdraw(), state is updated (pending withdrawal recorded), external call triggers reentrancy
 *    - **During reentrancy**: Attacker can observe inflated `totalPendingWithdrawals` state and exploit the inconsistency
 *    - **Transaction 2**: If original call fails and throws, state remains inconsistent, allowing manipulation in subsequent transactions
 *    - **Transaction 3+**: Multiple withdrawals can be queued up, creating accumulated state that can be exploited
 * 
 * 4. **State accumulation requirement**: The vulnerability requires building up state over multiple transactions - single transaction exploitation is not possible because the state inconsistency needs to persist and be leveraged across multiple calls
 * 
 * 5. **Realistic vulnerability pattern**: This mirrors real-world reentrancy patterns where state tracking systems create windows for exploitation during external calls
 * 
 * The vulnerability is only exploitable through multiple transactions because:
 * - State must accumulate in pendingWithdrawals across calls
 * - Reentrancy exploitation requires the inconsistent state to persist beyond a single transaction
 * - The attacker needs multiple opportunities to observe and manipulate the accumulated state
 * - Single transaction cannot fully exploit the state tracking mechanism
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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => uint) public pendingWithdrawals;
    uint public totalPendingWithdrawals;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    /*
     *  Types
     */
    struct EarlyPurchase {
        address purchaser;
        uint amount;        // Amount in Wei( = 1/ 10^18 Ether)
        uint purchasedAt;   // timestamp
    }

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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    function withdraw(uint withdrawalAmount) onlyOwner {
        // Add withdrawal to pending queue - state change before external call
        pendingWithdrawals[owner] += withdrawalAmount;
        totalPendingWithdrawals += withdrawalAmount;
        
        // External call that can trigger reentrancy
        if(!owner.send(withdrawalAmount)) {
            // On failure, leave pending withdrawal in inconsistent state
            throw;
        }
        
        // State cleanup happens after external call - vulnerable to reentrancy
        pendingWithdrawals[owner] -= withdrawalAmount;
        totalPendingWithdrawals -= withdrawalAmount;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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
