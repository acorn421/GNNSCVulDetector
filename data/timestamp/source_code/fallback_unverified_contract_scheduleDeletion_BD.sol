/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleDeletion
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This injection introduces a timestamp dependence vulnerability through ad deletion scheduling and activity tracking. The vulnerability is stateful and requires multiple transactions:
 * 
 * 1. Transaction 1: scheduleDeletion() - Sets deletion schedule using 'now' timestamp
 * 2. Transaction 2: executeDeletion() - Checks if scheduled time has passed using 'now' 
 * 3. Transaction 3: checkAdActivity() - Updates last accessed time using 'now'
 * 4. Transaction 4: cleanupInactiveAds() - Calculates time differences using 'now'
 * 
 * The vulnerability allows miners to manipulate timestamps to:
 * - Bypass deletion schedules by setting timestamps earlier than expected
 * - Prematurely trigger cleanup of active ads
 * - Manipulate activity tracking to protect certain ads from cleanup
 * 
 * The state persists across transactions through adDeletionSchedule and adLastAccessed mappings, making this a multi-transaction vulnerability that requires accumulated state changes to exploit.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    /// Mapping to track deletion schedules for ads
    mapping(uint => uint) public adDeletionSchedule;
    
    /// Track when ads were last accessed for activity monitoring
    mapping(uint => uint) public adLastAccessed;
    // === END FALLBACK INJECTION ===

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
    function withdraw() {
        require(msg.sender == contractOwner);
        withdrawWallet.transfer(this.balance);
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    
    /// scheduleDeletion allows ad owners to schedule deletion of their ads
    /// This is vulnerable to timestamp manipulation by miners
    function scheduleDeletion(uint _idx, uint _deletionTime) {
        Ad storage ad = ads[_idx];
        require(msg.sender == ad.owner);
        require(_deletionTime > now); // Vulnerable to timestamp manipulation
        
        adDeletionSchedule[_idx] = _deletionTime;
        adLastAccessed[_idx] = now; // Also vulnerable to timestamp manipulation
    }
    
    /// executeDeletion removes the ad if the scheduled time has passed
    /// This creates a multi-transaction vulnerability requiring state persistence
    function executeDeletion(uint _idx) {
        require(adDeletionSchedule[_idx] > 0);
        require(now >= adDeletionSchedule[_idx]); // Vulnerable to timestamp manipulation
        
        Ad storage ad = ads[_idx];
        
        // Clear the grid cells
        for(uint i=0; i<ad.width; i++) {
            for(uint j=0; j<ad.height; j++) {
                grid[ad.x+i][ad.y+j] = false;
            }
        }
        
        // Clear the ad data
        ad.owner = address(0);
        ad.link = "";
        ad.image = "";
        ad.title = "";
        ad.NSFW = false;
        ad.forceNSFW = false;
        
        // Clear the deletion schedule
        adDeletionSchedule[_idx] = 0;
        adLastAccessed[_idx] = 0;
    }
    
    /// checkAdActivity verifies if an ad has been accessed recently
    /// Used for automated cleanup of inactive ads
    function checkAdActivity(uint _idx) {
        require(msg.sender == contractOwner);
        require(_idx < ads.length);
        
        adLastAccessed[_idx] = now; // Vulnerable to timestamp manipulation
    }
    
    /// cleanupInactiveAds removes ads that haven't been accessed for a long time
    /// This creates a complex multi-transaction vulnerability
    function cleanupInactiveAds(uint _idx, uint _inactivityThreshold) {
        require(msg.sender == contractOwner);
        require(_idx < ads.length);
        require(_inactivityThreshold > 0);
        require(adLastAccessed[_idx] > 0);
        require(now - adLastAccessed[_idx] >= _inactivityThreshold); // Vulnerable calculation
        
        Ad storage ad = ads[_idx];
        
        // Clear the grid cells
        for(uint i=0; i<ad.width; i++) {
            for(uint j=0; j<ad.height; j++) {
                grid[ad.x+i][ad.y+j] = false;
            }
        }
        
        // Clear the ad data
        ad.owner = address(0);
        ad.link = "";
        ad.image = "";
        ad.title = "";
        ad.NSFW = false;
        ad.forceNSFW = false;
        
        // Clear tracking data
        adDeletionSchedule[_idx] = 0;
        adLastAccessed[_idx] = 0;
    }
    // === END FALLBACK INJECTION ===
}
