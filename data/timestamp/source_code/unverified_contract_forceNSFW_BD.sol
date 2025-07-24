/*
 * ===== SmartInject Injection Details =====
 * Function      : forceNSFW
 * Vulnerability : Timestamp Dependence
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
 * Introduced a time-based NSFW enforcement system that creates a multi-transaction timestamp dependence vulnerability. The vulnerability allows manipulation of NSFW status through timestamp-dependent logic:
 * 
 * **Key Changes Made:**
 * 1. Added timestamp-based expiration logic using `block.timestamp + 86400` (24 hours)
 * 2. Introduced `ad.nsfwExpirationTime` state variable to track expiration times
 * 3. Created conditional logic that behaves differently based on current timestamp vs stored expiration time
 * 4. Added auto-expiration check that removes NSFW status when time period expires
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Contract owner calls `forceNSFW(_idx, true)` to mark ad as NSFW with 24-hour expiration
 * 2. **Transaction 2**: After some time passes, attacker calls `forceNSFW(_idx, false)` but since expiration hasn't passed, it extends the NSFW period instead of removing it
 * 3. **Transaction 3**: Attacker waits until exactly the expiration time and calls `forceNSFW(_idx, false)` again, which now successfully removes NSFW status due to expired timestamp
 * 4. **Transaction 4**: Ad owner can now publish inappropriate content that bypasses NSFW restrictions
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires state accumulation through the `nsfwExpirationTime` field that persists between transactions
 * - Timing manipulation requires multiple calls at different timestamps to exploit the conditional logic
 * - The auto-expiration mechanism creates windows of opportunity that can only be exploited through sequential transactions
 * - Attackers need to observe timestamp changes across multiple blocks to time their exploitation correctly
 * 
 * **Realistic Attack Vector:**
 * Miners or attackers with timestamp manipulation capabilities can predict future block timestamps and time their transactions to exploit the automatic expiration logic, potentially bypassing content moderation controls across multiple transactions.
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
        /// Timestamp when forceNSFW expires; 0 means no expiration set
        uint nsfwExpirationTime;
    }

    /// ads are stored in an array, the id of an ad is its index in this array.
    Ad[] public ads;

    constructor(address _contractOwner, address _withdrawWallet) public {
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
                }
                grid[_x+i][_y+j] = true;
            }
        }

        // We reserved space in the grid, now make a placeholder entry.
        Ad memory ad = Ad(msg.sender, _x, _y, _width, _height, "", "", "", false, false, 0);
        idx = ads.push(ad) - 1;
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====

        // Time-based NSFW enforcement with automatic expiration
        if (_NSFW) {
            // Set NSFW with timestamp-based expiration (24 hours)
            ad.forceNSFW = true;
            ad.nsfwExpirationTime = block.timestamp + 86400; // 24 hours from now
        } else {
            // Only allow removal if enough time has passed since last enforcement
            if (ad.nsfwExpirationTime > 0 && block.timestamp >= ad.nsfwExpirationTime) {
                ad.forceNSFW = false;
                ad.nsfwExpirationTime = 0;
            } else if (ad.nsfwExpirationTime > 0) {
                // Still within enforcement period, extend by another 24 hours
                ad.nsfwExpirationTime = block.timestamp + 86400;
            }
        }

        // Check if NSFW enforcement has expired and auto-remove
        if (ad.forceNSFW && ad.nsfwExpirationTime > 0 && block.timestamp >= ad.nsfwExpirationTime) {
            ad.forceNSFW = false;
            ad.nsfwExpirationTime = 0;
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

        emit Publish(_idx, ad.link, ad.image, ad.title, ad.NSFW || ad.forceNSFW);
    }

    /// withdraw allows the owner to transfer out the balance of the contract.
    function withdraw() public {
        require(msg.sender == contractOwner);
        withdrawWallet.transfer(this.balance);
    }
}
