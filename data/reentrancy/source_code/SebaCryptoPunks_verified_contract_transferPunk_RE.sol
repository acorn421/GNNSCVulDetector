/*
 * ===== SmartInject Injection Details =====
 * Function      : transferPunk
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: Created `transferCallbackEnabled` and `transferCallbackGas` mappings to track callback preferences for each address, enabling stateful behavior across transactions.
 * 
 * 2. **Separated State Updates**: Moved the ownership update (`punkIndexToAddress[punkIndex] = to`) before the external call, while keeping balance updates (`balanceOf` modifications) after the external call, creating a vulnerable window.
 * 
 * 3. **Introduced External Call**: Added an external call to the recipient contract using `to.call.gas()` that invokes an `onPunkReceived` callback, creating the reentrancy opportunity.
 * 
 * 4. **Multi-Transaction Setup**: The vulnerability requires multiple transactions:
 *    - **Transaction 1**: Attacker calls `enableTransferCallback()` to set up callback state
 *    - **Transaction 2**: Victim calls `transferPunk()` to attacker's malicious contract
 *    - **During callback**: Malicious contract re-enters `transferPunk()` while balances are inconsistent
 *    - **Transaction 3+**: Attacker exploits the state inconsistency
 * 
 * 5. **Exploitation Scenario**:
 *    - **Setup Phase**: Attacker deploys malicious contract and calls `enableTransferCallback(50000)` to register for callbacks
 *    - **Trigger Phase**: When someone transfers a punk to the malicious contract, it receives the callback BEFORE balance updates
 *    - **Exploit Phase**: During the callback, ownership is updated but balances are not, allowing the malicious contract to:
 *      - See itself as the new owner in `punkIndexToAddress`
 *      - But victim's balance hasn't been decremented yet
 *      - Malicious contract can call `transferPunk()` again to transfer the punk elsewhere
 *      - This creates double-spending: punk is transferred twice but balance only decremented once
 * 
 * 6. **Why Multi-Transaction**: 
 *    - The callback registration must happen in a separate transaction before the vulnerable transfer
 *    - The exploit requires the specific sequence: callback registration → transfer call → reentrancy during callback
 *    - Each phase requires separate transactions, making this a true multi-transaction vulnerability
 * 
 * The vulnerability is realistic because callback mechanisms are common in modern smart contracts for notifications, and the state separation creates a genuine race condition exploitable across multiple transactions.
 */
pragma solidity ^0.4.8;
// Modified version of original crypto punks contract. 
// Contract name changed and total supply set to 100000
contract SebaCryptoPunks {

    // You can use this hash to verify the image file containing all the punks
    string public imageHash = "ac39af4793119ee46bbff351d8cb6b5f23da60222126add4268e261199a2921b";

    address owner;

    string public standard = 'SebaCryptoPunks';
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    uint public nextPunkIndexToAssign = 0;

    bool public allPunksAssigned = true;
    uint public punksRemainingToAssign = 0;

    //mapping (address => uint) public addressToPunkIndex;
    mapping (uint => address) public punkIndexToAddress;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;

    struct Offer {
        bool isForSale;
        uint punkIndex;
        address seller;
        uint minValue;          // in ether
        address onlySellTo;     // specify to sell only to a specific person
    }

    struct Bid {
        bool hasBid;
        uint punkIndex;
        address bidder;
        uint value;
    }

    // A record of punks that are offered for sale at a specific minimum value, and perhaps to a specific person
    mapping (uint => Offer) public punksOfferedForSale;

    // A record of the highest punk bid
    mapping (uint => Bid) public punkBids;

    mapping (address => uint) public pendingWithdrawals;

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping (address => bool) public transferCallbackEnabled;
    mapping (address => uint) public transferCallbackGas;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    event Assign(address indexed to, uint256 punkIndex);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event PunkTransfer(address indexed from, address indexed to, uint256 punkIndex);
    event PunkOffered(uint indexed punkIndex, uint minValue, address indexed toAddress);
    event PunkBidEntered(uint indexed punkIndex, uint value, address indexed fromAddress);
    event PunkBidWithdrawn(uint indexed punkIndex, uint value, address indexed fromAddress);
    event PunkBought(uint indexed punkIndex, uint value, address indexed fromAddress, address indexed toAddress);
    event PunkNoLongerForSale(uint indexed punkIndex);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function SebaCryptoPunks() payable {
        //        balanceOf[msg.sender] = initialSupply;              // Give the creator all initial tokens
        owner = msg.sender;
        totalSupply = 100000;                        // Update total supply
        punksRemainingToAssign = totalSupply;
        name = "SEBA-CRYPTOPUNKS";                                   // Set the name for display purposes
        symbol = "Ͼ";                               // Set the symbol for display purposes
        decimals = 0;                                       // Amount of decimals for display purposes
    }

    function setInitialOwner(address to, uint punkIndex) {
        if (msg.sender != owner) throw;
        if (allPunksAssigned) throw;
        if (punkIndex >= 100000) throw;
        if (punkIndexToAddress[punkIndex] != to) {
            if (punkIndexToAddress[punkIndex] != 0x0) {
                balanceOf[punkIndexToAddress[punkIndex]]--;
            } else {
                punksRemainingToAssign--;
            }
            punkIndexToAddress[punkIndex] = to;
            balanceOf[to]++;
            Assign(to, punkIndex);
        }
    }

    function setInitialOwners(address[] addresses, uint[] indices) {
        if (msg.sender != owner) throw;
        uint n = addresses.length;
        for (uint i = 0; i < n; i++) {
            setInitialOwner(addresses[i], indices[i]);
        }
    }

    function allInitialOwnersAssigned() {
        if (msg.sender != owner) throw;
        allPunksAssigned = true;
    }

    function getPunk(uint punkIndex) {
        if (!allPunksAssigned) throw;
        if (punksRemainingToAssign == 0) throw;
        if (punkIndexToAddress[punkIndex] != 0x0) throw;
        if (punkIndex >= 100000) throw;
        punkIndexToAddress[punkIndex] = msg.sender;
        balanceOf[msg.sender]++;
        punksRemainingToAssign--;
        Assign(msg.sender, punkIndex);
    }

    // Transfer ownership of a punk to another user without requiring payment
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    function transferPunk(address to, uint punkIndex) {
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if (!allPunksAssigned) throw;
        if (punkIndexToAddress[punkIndex] != msg.sender) throw;
        if (punkIndex >= 100000) throw;
        if (punksOfferedForSale[punkIndex].isForSale) {
            punkNoLongerForSale(punkIndex);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update ownership but delay balance updates to create reentrancy window
        address previousOwner = msg.sender;
        punkIndexToAddress[punkIndex] = to;
        
        // Notify recipient contract before completing all state updates
        if (transferCallbackEnabled[to]) {
            uint gasAmount = transferCallbackGas[to] > 0 ? transferCallbackGas[to] : 21000;
            // External call before balance updates - creates reentrancy vulnerability
            bool success = to.call.gas(gasAmount)(bytes4(keccak256("onPunkReceived(address,uint256)")), previousOwner, punkIndex);
        }
        
        // Balance updates happen after external call - vulnerable to reentrancy
        balanceOf[previousOwner]--;
        balanceOf[to]++;
        Transfer(previousOwner, to, 1);
        PunkTransfer(previousOwner, to, punkIndex);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        // Check for the case where there is a bid from the new owner and refund it.
        // Any other bid can stay in place.
        Bid bid = punkBids[punkIndex];
        if (bid.bidder == to) {
            // Kill bid and refund value
            pendingWithdrawals[to] += bid.value;
            punkBids[punkIndex] = Bid(false, punkIndex, 0x0, 0);
        }
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    function enableTransferCallback(uint gasAmount) {
        transferCallbackEnabled[msg.sender] = true;
        transferCallbackGas[msg.sender] = gasAmount;
    }
    
    function disableTransferCallback() {
        transferCallbackEnabled[msg.sender] = false;
        transferCallbackGas[msg.sender] = 0;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    function punkNoLongerForSale(uint punkIndex) {
        if (!allPunksAssigned) throw;
        if (punkIndexToAddress[punkIndex] != msg.sender) throw;
        if (punkIndex >= 100000) throw;
        punksOfferedForSale[punkIndex] = Offer(false, punkIndex, msg.sender, 0, 0x0);
        PunkNoLongerForSale(punkIndex);
    }

    function offerPunkForSale(uint punkIndex, uint minSalePriceInWei) {
        if (!allPunksAssigned) throw;
        if (punkIndexToAddress[punkIndex] != msg.sender) throw;
        if (punkIndex >= 100000) throw;
        punksOfferedForSale[punkIndex] = Offer(true, punkIndex, msg.sender, minSalePriceInWei, 0x0);
        PunkOffered(punkIndex, minSalePriceInWei, 0x0);
    }

    function offerPunkForSaleToAddress(uint punkIndex, uint minSalePriceInWei, address toAddress) {
        if (!allPunksAssigned) throw;
        if (punkIndexToAddress[punkIndex] != msg.sender) throw;
        if (punkIndex >= 100000) throw;
        punksOfferedForSale[punkIndex] = Offer(true, punkIndex, msg.sender, minSalePriceInWei, toAddress);
        PunkOffered(punkIndex, minSalePriceInWei, toAddress);
    }

    function buyPunk(uint punkIndex) payable {
        if (!allPunksAssigned) throw;
        Offer offer = punksOfferedForSale[punkIndex];
        if (punkIndex >= 100000) throw;
        if (!offer.isForSale) throw;                // punk not actually for sale
        if (offer.onlySellTo != 0x0 && offer.onlySellTo != msg.sender) throw;  // punk not supposed to be sold to this user
        if (msg.value < offer.minValue) throw;      // Didn't send enough ETH
        if (offer.seller != punkIndexToAddress[punkIndex]) throw; // Seller no longer owner of punk

        address seller = offer.seller;

        punkIndexToAddress[punkIndex] = msg.sender;
        balanceOf[seller]--;
        balanceOf[msg.sender]++;
        Transfer(seller, msg.sender, 1);

        punkNoLongerForSale(punkIndex);
        pendingWithdrawals[seller] += msg.value;
        PunkBought(punkIndex, msg.value, seller, msg.sender);

        // Check for the case where there is a bid from the new owner and refund it.
        // Any other bid can stay in place.
        Bid bid = punkBids[punkIndex];
        if (bid.bidder == msg.sender) {
            // Kill bid and refund value
            pendingWithdrawals[msg.sender] += bid.value;
            punkBids[punkIndex] = Bid(false, punkIndex, 0x0, 0);
        }
    }

    function withdraw() {
        if (!allPunksAssigned) throw;
        uint amount = pendingWithdrawals[msg.sender];
        // Remember to zero the pending refund before
        // sending to prevent re-entrancy attacks
        pendingWithdrawals[msg.sender] = 0;
        msg.sender.transfer(amount);
    }

    function enterBidForPunk(uint punkIndex) payable {
        if (punkIndex >= 100000) throw;
        if (!allPunksAssigned) throw;                
        if (punkIndexToAddress[punkIndex] == 0x0) throw;
        if (punkIndexToAddress[punkIndex] == msg.sender) throw;
        if (msg.value == 0) throw;
        Bid existing = punkBids[punkIndex];
        if (msg.value <= existing.value) throw;
        if (existing.value > 0) {
            // Refund the failing bid
            pendingWithdrawals[existing.bidder] += existing.value;
        }
        punkBids[punkIndex] = Bid(true, punkIndex, msg.sender, msg.value);
        PunkBidEntered(punkIndex, msg.value, msg.sender);
    }

    function acceptBidForPunk(uint punkIndex, uint minPrice) {
        if (punkIndex >= 100000) throw;
        if (!allPunksAssigned) throw;                
        if (punkIndexToAddress[punkIndex] != msg.sender) throw;
        address seller = msg.sender;
        Bid bid = punkBids[punkIndex];
        if (bid.value == 0) throw;
        if (bid.value < minPrice) throw;

        punkIndexToAddress[punkIndex] = bid.bidder;
        balanceOf[seller]--;
        balanceOf[bid.bidder]++;
        Transfer(seller, bid.bidder, 1);

        punksOfferedForSale[punkIndex] = Offer(false, punkIndex, bid.bidder, 0, 0x0);
        uint amount = bid.value;
        punkBids[punkIndex] = Bid(false, punkIndex, 0x0, 0);
        pendingWithdrawals[seller] += amount;
        PunkBought(punkIndex, bid.value, seller, bid.bidder);
    }

    function withdrawBidForPunk(uint punkIndex) {
        if (punkIndex >= 100000) throw;
        if (!allPunksAssigned) throw;                
        if (punkIndexToAddress[punkIndex] == 0x0) throw;
        if (punkIndexToAddress[punkIndex] == msg.sender) throw;
        Bid bid = punkBids[punkIndex];
        if (bid.bidder != msg.sender) throw;
        PunkBidWithdrawn(punkIndex, bid.value, msg.sender);
        uint amount = bid.value;
        punkBids[punkIndex] = Bid(false, punkIndex, 0x0, 0);
        // Refund the bid money
        msg.sender.transfer(amount);
    }

}
