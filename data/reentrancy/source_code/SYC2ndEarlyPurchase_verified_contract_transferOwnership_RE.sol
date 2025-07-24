/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added Persistent State**: Created `ownershipTransferPending` mapping to track pending ownership transfers across transactions
 * 2. **External Call Before State Update**: Added `newOwner.call()` before the critical `owner = newOwner` assignment, violating the checks-effects-interactions pattern
 * 3. **Vulnerable State Window**: The pending state persists between transactions when the external call fails, creating opportunities for exploitation
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Current owner calls `transferOwnership(maliciousContract)`
 * - `ownershipTransferPending[maliciousContract] = true` is set
 * - External call to `maliciousContract.onOwnershipTransferred()` is made
 * - Malicious contract can reenter and call other `onlyOwner` functions while `owner` is still the original owner
 * - If the external call fails or malicious contract makes it fail, ownership doesn't transfer but pending state remains
 * 
 * **Transaction 2+ (Exploitation):**
 * - The `ownershipTransferPending` state persists, indicating a failed transfer
 * - Malicious contract can monitor this state and exploit the fact that other functions might check `ownershipTransferPending` for additional privileges
 * - In subsequent transactions, the malicious contract can trigger the external call again, creating more reentrancy opportunities
 * - Each failed attempt leaves the contract in an inconsistent state where pending transfer exists but ownership hasn't changed
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires persistent state (`ownershipTransferPending`) to accumulate across transactions
 * - The exploit depends on the external call failing in one transaction, leaving vulnerable state for future transactions
 * - Reentrancy attacks during the external call can access the original owner's privileges while the transfer is pending
 * - Multiple attempts can be made to exploit the vulnerable state window, with each attempt potentially causing different state changes
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
    mapping(address => bool) private ownershipTransferPending;
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

    function withdraw(uint withdrawalAmount) onlyOwner {
          if(!owner.send(withdrawalAmount)) throw;  // send collected ETH to SynchroLife team
    }

    function withdrawAll() onlyOwner {
          if(!owner.send(this.balance)) throw;  // send all collected ETH to SynchroLife team
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    function transferOwnership(address newOwner) onlyOwner {
        // Mark ownership transfer as pending
        ownershipTransferPending[newOwner] = true;
        
        // Notify the new owner about pending ownership transfer
        // This external call happens before ownership is actually transferred
        if (newOwner.call(bytes4(keccak256("onOwnershipTransferred(address)")), owner)) {
            // If notification successful, complete the transfer
            owner = newOwner;
            ownershipTransferPending[newOwner] = false;
        } else {
            // If notification fails, keep pending state for retry
            // This creates a vulnerable window where pending state persists
        }
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    /// @dev By sending Ether to the contract, early purchase will be recorded.
    function () payable{
        require(msg.value >= WEI_MINIMUM_PURCHASE);
        appendEarlyPurchase(msg.sender, msg.value, now);
    }
}
