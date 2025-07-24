/*
 * ===== SmartInject Injection Details =====
 * Function      : withdraw
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **State Variables Added**: 
 *    - `pendingWithdrawals` mapping tracks pending withdrawal amounts
 *    - `withdrawalInProgress` flag indicates withdrawal state
 *    - `totalPendingAmount` accumulates total pending withdrawals
 * 
 * 2. **Multi-Transaction Exploitation Pattern**:
 *    - **Transaction 1**: Contract owner calls withdraw(), setting withdrawalInProgress=true and recording pending amount
 *    - **Transaction 2**: During the external call, if withdrawWallet is a malicious contract, it can re-enter withdraw()
 *    - **Transaction 3+**: The malicious contract can continue calling withdraw() while pendingWithdrawals state persists
 * 
 * 3. **Vulnerability Mechanics**:
 *    - The external call `withdrawWallet.call.value()` happens before proper state cleanup
 *    - `pendingWithdrawals[withdrawWallet]` is never reset to 0 after successful withdrawal
 *    - The `withdrawalInProgress` flag is reset after the external call, creating a vulnerable window
 *    - Multiple withdrawals can be processed against the same pending amount
 * 
 * 4. **Multi-Transaction Requirement**: 
 *    - The vulnerability requires the withdrawWallet to be a malicious contract with fallback/receive function
 *    - The first transaction sets up the vulnerable state
 *    - Subsequent reentrancy calls exploit the persistent state across multiple transaction contexts
 *    - The exploit accumulates over multiple calls as pendingWithdrawals state persists
 * 
 * 5. **Exploitation Scenario**:
 *    - Owner calls withdraw() → sets pending state and calls external contract
 *    - Malicious withdrawWallet contract receives funds and immediately calls withdraw() again
 *    - Since pendingWithdrawals wasn't reset, second call processes the same amount again
 *    - This can continue until contract balance is drained
 * 
 * This creates a realistic reentrancy vulnerability that requires multiple transactions and persistent state to exploit, making it stateful and multi-transaction dependent.
 */
pragma solidity ^0.4.15;

contract KetherHomepage {
    /// Buy is emitted when an ad unit is reserved.
    event Buy(
        uint indexed idx,
        address owner,
        uint x,
        uint y,
        uint width,
        uint height
    );

    /// Publish is emitted whenever the contents of an ad is changed.
    event Publish(
        uint indexed idx,
        string link,
        string image,
        string title,
        bool NSFW
    );

    /// SetAdOwner is emitted whenever the ownership of an ad is transfered
    event SetAdOwner(
        uint indexed idx,
        address from,
        address to
    );

    /// Price is 1 kether divided by 1,000,000 pixels
    uint public constant weiPixelPrice = 1000000000000000;

    /// Each grid cell represents 100 pixels (10x10).
    uint public constant pixelsPerCell = 100;

    bool[100][100] public grid;

    /// contractOwner can withdraw the funds and override NSFW status of ad units.
    address contractOwner;

    /// withdrawWallet is the fixed destination of funds to withdraw. It is
    /// separate from contractOwner to allow for a cold storage destination.
    address withdrawWallet;

    struct Ad {
        address owner;
        uint x;
        uint y;
        uint width;
        uint height;
        string link;
        string image;
        string title;

        /// NSFW is whether the ad is suitable for people of all
        /// ages and workplaces.
        bool NSFW;
        /// forceNSFW can be set by owner.
        bool forceNSFW;
    }

    /// ads are stored in an array, the id of an ad is its index in this array.
    Ad[] public ads;

    function KetherHomepage(address _contractOwner, address _withdrawWallet) {
        require(_contractOwner != address(0));
        require(_withdrawWallet != address(0));

        contractOwner = _contractOwner;
        withdrawWallet = _withdrawWallet;
    }

    /// getAdsLength tells you how many ads there are
    function getAdsLength() constant returns (uint) {
        return ads.length;
    }

    /// Ads must be purchased in 10x10 pixel blocks.
    /// Each coordinate represents 10 pixels. That is,
    ///   _x=5, _y=10, _width=3, _height=3
    /// Represents a 30x30 pixel ad at coordinates (50, 100)
    function buy(uint _x, uint _y, uint _width, uint _height) payable returns (uint idx) {
        uint cost = _width * _height * pixelsPerCell * weiPixelPrice;
        require(cost > 0);
        require(msg.value >= cost);

        // Loop over relevant grid entries
        for(uint i=0; i<_width; i++) {
            for(uint j=0; j<_height; j++) {
                if (grid[_x+i][_y+j]) {
                    // Already taken, undo.
                    revert();
                }
                grid[_x+i][_y+j] = true;
            }
        }

        // We reserved space in the grid, now make a placeholder entry.
        Ad memory ad = Ad(msg.sender, _x, _y, _width, _height, "", "", "", false, false);
        idx = ads.push(ad) - 1;
        Buy(idx, msg.sender, _x, _y, _width, _height);
        return idx;
    }

    /// Publish allows for setting the link, image, and NSFW status for the ad
    /// unit that is identified by the idx which was returned during the buy step.
    /// The link and image must be full web3-recognizeable URLs, such as:
    ///  - bzz://a5c10851ef054c268a2438f10a21f6efe3dc3dcdcc2ea0e6a1a7a38bf8c91e23
    ///  - bzz://mydomain.eth/ad.png
    ///  - https://cdn.mydomain.com/ad.png
    /// Images should be valid PNG.
    function publish(uint _idx, string _link, string _image, string _title, bool _NSFW) {
        Ad storage ad = ads[_idx];
        require(msg.sender == ad.owner);
        ad.link = _link;
        ad.image = _image;
        ad.title = _title;
        ad.NSFW = _NSFW;

        Publish(_idx, ad.link, ad.image, ad.title, ad.NSFW || ad.forceNSFW);
    }

    /// setAdOwner changes the owner of an ad unit
    function setAdOwner(uint _idx, address _newOwner) {
        Ad storage ad = ads[_idx];
        require(msg.sender == ad.owner);
        ad.owner = _newOwner;

        SetAdOwner(_idx, msg.sender, _newOwner);
    }

    /// forceNSFW allows the owner to override the NSFW status for a specific ad unit.
    function forceNSFW(uint _idx, bool _NSFW) {
        require(msg.sender == contractOwner);
        Ad storage ad = ads[_idx];
        ad.forceNSFW = _NSFW;

        Publish(_idx, ad.link, ad.image, ad.title, ad.NSFW || ad.forceNSFW);
    }

    /// withdraw allows the owner to transfer out the balance of the contract.
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint) public pendingWithdrawals;
    bool public withdrawalInProgress;
    uint public totalPendingAmount;

    function withdraw() {
        require(msg.sender == contractOwner);
        
        if (!withdrawalInProgress) {
            // First transaction: Initialize withdrawal request
            withdrawalInProgress = true;
            uint currentBalance = this.balance;
            pendingWithdrawals[withdrawWallet] += currentBalance;
            totalPendingAmount += currentBalance;
            
            // External call that enables reentrancy before state cleanup
            withdrawWallet.call.value(currentBalance)("");
            
            // State reset happens after external call - vulnerable window
            withdrawalInProgress = false;
        } else {
            // Subsequent transactions during withdrawal process
            uint pendingAmount = pendingWithdrawals[withdrawWallet];
            if (pendingAmount > 0 && this.balance >= pendingAmount) {
                // External call without proper state reset
                withdrawWallet.call.value(pendingAmount)("");
                // Vulnerable: pendingWithdrawals not reset, allows multiple withdrawals
            }
        }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
}