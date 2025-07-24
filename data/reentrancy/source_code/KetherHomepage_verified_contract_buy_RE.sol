/*
 * ===== SmartInject Injection Details =====
 * Function      : buy
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Vulnerability Injection: Stateful Multi-Transaction Reentrancy**
 * 
 * **Specific Changes Made:**
 * 
 * 1. **Split Grid State Logic**: The original function checked and immediately set grid[_x+i][_y+j] = true in one loop. I split this into two phases:
 *    - Phase 1: Check if grid cells are available (lines 7-14)
 *    - Phase 2: Actually reserve the grid cells (lines 23-27)
 * 
 * 2. **Added External Call Between Phases**: Introduced an external call for refunding excess payment (lines 19-21) that occurs BETWEEN the availability check and the actual grid reservation.
 * 
 * 3. **Vulnerable State Ordering**: The critical state update (setting grid cells to true) now happens AFTER the external call, creating a classic reentrancy vulnerability.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1: Initial Setup**
 * - Attacker deploys a malicious contract that implements a fallback function
 * - Attacker calls buy() with coordinates (5,5,2,2) and sends excess ETH to trigger refund
 * 
 * **Transaction 2: Reentrancy Exploitation**
 * - When the refund call executes `msg.sender.call.value(msg.value - cost)("")`, it triggers the attacker's fallback function
 * - Inside the fallback, the attacker re-enters buy() for overlapping coordinates (e.g., 6,6,2,2)
 * - The grid state is still not updated from the first call, so the overlap check passes
 * - Both transactions successfully reserve overlapping grid space
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Persistence**: The ads array grows with each successful purchase, creating accumulated state across transactions
 * 2. **Grid Reservation Race**: Multiple transactions can check grid availability simultaneously before any updates occur
 * 3. **Payment Accumulation**: Each transaction processes payment and creates ads entries, building up contract state
 * 4. **Timing Dependency**: The vulnerability relies on the specific timing of state updates across transaction boundaries
 * 
 * **Exploitation Requirements:**
 * - **Transaction 1**: Normal buy() call that triggers the external refund call
 * - **Reentrant Transaction**: During the external call, re-enter buy() with overlapping coordinates
 * - **State Accumulation**: Multiple successful purchases create inconsistent grid state and ads entries
 * - **Cross-Transaction Impact**: The vulnerability's effects (overlapping reservations) persist and compound across multiple transactions
 * 
 * This creates a realistic, stateful reentrancy vulnerability that requires multiple transactions to exploit and results in permanent state corruption that persists beyond the initial attack.
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

    // Constructor
    function KetherHomepage(address _contractOwner, address _withdrawWallet) public {
        require(_contractOwner != address(0));
        require(_withdrawWallet != address(0));

        contractOwner = _contractOwner;
        withdrawWallet = _withdrawWallet;
    }

    /// getAdsLength tells you how many ads there are
    function getAdsLength() public constant returns (uint) {
        return ads.length;
    }

    /// Ads must be purchased in 10x10 pixel blocks.
    /// Each coordinate represents 10 pixels. That is,
    ///   _x=5, _y=10, _width=3, _height=3
    /// Represents a 30x30 pixel ad at coordinates (50, 100)
    function buy(uint _x, uint _y, uint _width, uint _height) public payable returns (uint idx) {
        uint cost = _width * _height * pixelsPerCell * weiPixelPrice;
        require(cost > 0);
        require(msg.value >= cost);

        // Loop over relevant grid entries
        for(uint i=0; i<_width; i++) {
            for(uint j=0; j<_height; j++) {
                if (grid[_x+i][_y+j]) {
                    // Already taken, undo.
                    revert();
                // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
                }
            }
        }

        // We reserved space in the grid, now make a placeholder entry.
        Ad memory ad = Ad(msg.sender, _x, _y, _width, _height, "", "", "", false, false);
        idx = ads.push(ad) - 1;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Refund excess payment to buyer - VULNERABLE: external call before state finalization
        if (msg.value > cost) {
            // Return value deliberately ignored to preserve vulnerability
            msg.sender.call.value(msg.value - cost)("");
        }
        
        // Actually reserve grid space AFTER external call - VULNERABLE STATE ORDERING
        for(uint i2=0; i2<_width; i2++) {
            for(uint j2=0; j2<_height; j2++) {
                grid[_x+i2][_y+j2] = true;
            }
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Buy(idx, msg.sender, _x, _y, _width, _height);
        return idx;
    }

    /// Publish allows for setting the link, image, and NSFW status for the ad
    /// unit that is identified by the idx which was returned during the buy step.
    /// The link and image must be full web3-recognizeable URLs, such as:
    ///  - bzz://a5c10851ef054c268a2438f10a21f6efe3dc3dcdcc2ea0e6a1a7a38bf8c91e23
    ///  - bzz://mydomain.eth/ad.png
    ///  - https://cdn.mydomain.com/ad.png
    /// Images should be valid PNG.
    function publish(uint _idx, string _link, string _image, string _title, bool _NSFW) public {
        Ad storage ad = ads[_idx];
        require(msg.sender == ad.owner);
        ad.link = _link;
        ad.image = _image;
        ad.title = _title;
        ad.NSFW = _NSFW;

        emit Publish(_idx, ad.link, ad.image, ad.title, ad.NSFW || ad.forceNSFW);
    }

    /// setAdOwner changes the owner of an ad unit
    function setAdOwner(uint _idx, address _newOwner) public {
        Ad storage ad = ads[_idx];
        require(msg.sender == ad.owner);
        ad.owner = _newOwner;

        emit SetAdOwner(_idx, msg.sender, _newOwner);
    }

    /// forceNSFW allows the owner to override the NSFW status for a specific ad unit.
    function forceNSFW(uint _idx, bool _NSFW) public {
        require(msg.sender == contractOwner);
        Ad storage ad = ads[_idx];
        ad.forceNSFW = _NSFW;

        emit Publish(_idx, ad.link, ad.image, ad.title, ad.NSFW || ad.forceNSFW);
    }

    /// withdraw allows the owner to transfer out the balance of the contract.
    function withdraw() public {
        require(msg.sender == contractOwner);
        withdrawWallet.transfer(address(this).balance);
    }
}
