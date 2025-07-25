/*
 * ===== SmartInject Injection Details =====
 * Function      : purchaseCompany
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful timestamp dependence vulnerability through a time-based volume bonus system that rewards quick succession purchases. The vulnerability requires storing block.timestamp in state variables (lastPurchaseTime) and using these timestamps for critical financial calculations. Multiple state variables (lastPurchaseTime, quickPurchaseStreak) persist between transactions and create compound effects.
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **First Transaction**: Attacker purchases a company, establishing the initial timestamp baseline
 * 2. **Second Transaction**: Within 1 hour, attacker purchases the same company again, receiving a 20% volume bonus
 * 3. **Subsequent Transactions**: Attacker continues purchasing within 1-hour windows to maintain streak bonuses
 * 
 * **State Accumulation:**
 * - lastPurchaseTime persists between transactions and affects future calculations
 * - quickPurchaseStreak accumulates across multiple transactions
 * - Volume bonuses compound over multiple purchases
 * 
 * **Timestamp Manipulation Attack Vector:**
 * - Miners can manipulate block.timestamp by up to 900 seconds (15 minutes) according to Ethereum protocol
 * - Attackers can time their transactions to artificially trigger the 1-hour bonus window
 * - The vulnerability requires multiple coordinated transactions to maximize exploitation
 * - Cannot be exploited in a single transaction as it requires comparison with previously stored timestamps
 */
pragma solidity ^0.4.18;

/*
Game Name: WallCryptoStreet
Game Link: https://wallcryptostreet.net/
Rules: 
- Players can purchase companies and sell shares & ads to the other players. 
- Company owners receive a commission of 80% for the initial sell of their shares and 10% on consecutive sales.
- When a company sell an ad, 50% of the revenue is distributed among the shareholders, 40% to you and 10% to us. 
- Ads are visible until someone else pays more than the previous user. 
- Companies, shares and ads can be acquired for 1.5x the amount paid.
*/

contract WallCryptoStreet {

    address ceoAddress = 0x9aFbaA3003D9e75C35FdE2D1fd283b13d3335f00;
    address cfoAddress = 0x23a49A9930f5b562c6B1096C3e6b5BEc133E8B2E;
    
    modifier onlyCeo() {
        require (msg.sender == ceoAddress);
        _;
    }
    
    struct Company {
        string name;
        address ownerAddress;
        uint256 curPrice;
        uint256 curAdPrice;
        string curAdText;
        string curAdLink;
        uint256 volume;
        uint256 lastPurchaseTime; // Added member
        uint256 quickPurchaseStreak; // Added member
    }
    Company[] companies;

    struct Share {
        uint companyId;
        address ownerAddress;
        uint256 curPrice;
    }
    Share[] shares;

    // How many shares an addres own
    mapping (address => uint) public addressSharesCount;
    bool companiesAreInitiated;
    bool isPaused;
    
    /*
    We use the following functions to pause and unpause the game.
    */
    function pauseGame() public onlyCeo {
        isPaused = true;
    }
    function unPauseGame() public onlyCeo {
        isPaused = false;
    }
    function GetIsPauded() public view returns(bool) {
       return(isPaused);
    }

    /*
    This function allows players to purchase companies from other players. 
    The price is automatically multiplied by 1.5 after each purchase.
    */
    function purchaseCompany(uint _companyId) public payable {
        require(msg.value == companies[_companyId].curPrice);
        require(isPaused == false);

        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Time-based volume bonus system - accumulates over multiple purchases
        uint256 timeSinceLastPurchase = block.timestamp - companies[_companyId].lastPurchaseTime;
        uint256 volumeMultiplier = 100; // Base 100%
        
        // Quick succession bonus: 20% bonus if purchased within 1 hour of last purchase
        if(timeSinceLastPurchase < 3600 && companies[_companyId].lastPurchaseTime > 0) {
            volumeMultiplier = 120;
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        // Calculate the 5% value
        uint256 commission5percent = ((msg.value / 10)/2);

        // Calculate the owner commission on this sale & transfer the commission to the owner.      
        uint256 commissionOwner = msg.value - commission5percent; // => 95%
        companies[_companyId].ownerAddress.transfer(commissionOwner);

        // Transfer the 5% commission to the developer
        cfoAddress.transfer(commission5percent); // => 5%                   

        // Update the company owner and set the new price
        companies[_companyId].ownerAddress = msg.sender;
        companies[_companyId].curPrice = companies[_companyId].curPrice + (companies[_companyId].curPrice / 2);
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Time-weighted volume calculation with bonus
        uint256 adjustedVolume = (msg.value * volumeMultiplier) / 100;
        companies[_companyId].volume = companies[_companyId].volume + adjustedVolume;
        
        // Store current timestamp for future time-based calculations
        companies[_companyId].lastPurchaseTime = block.timestamp;
        
        // Accumulate consecutive quick purchases for compound bonuses
        if(timeSinceLastPurchase < 3600 && companies[_companyId].lastPurchaseTime > 0) {
            companies[_companyId].quickPurchaseStreak++;
        } else {
            companies[_companyId].quickPurchaseStreak = 1;
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }
    
    /*
    We use this function to allow users to purchase advertisment from a listing. 
    Ad is visible until someone pays more than the previous user
    */
    function purchaseAd(uint _companyId, string adText, string adLink) public payable {
        require(msg.value == companies[_companyId].curAdPrice);

        // Save text and link for the ad
        companies[_companyId].curAdText = adText;
        companies[_companyId].curAdLink = adLink;

        // Distribute the money paid among investors, company owner and dev
        uint256 commission1percent = (msg.value / 100);
        companies[_companyId].ownerAddress.transfer(commission1percent * 40);   // Company owner gets 40% of the amount paid
        cfoAddress.transfer(commission1percent * 10);   // Dev gets a commission of 10% of the amount paid

        uint256 commissionShareholders = commission1percent * 50;   // 50% of the amount paid is distributed to shareholders
        uint256 commissionOneShareholder = commissionShareholders / 5;

        // Get the list of shareholders for this company
        address[] memory shareholdersAddresses = getCompanyShareholders(_companyId);
        // We loop thrugh all of the shareholders and transfer their commission
        for (uint8 i = 0; i < 5; i++) {
            shareholdersAddresses[i].transfer(commissionOneShareholder);
        }

        // Raise the price of the advertising
        companies[_companyId].curAdPrice = companies[_companyId].curAdPrice + (companies[_companyId].curAdPrice / 2);

        // Increment volume generated by company
        companies[_companyId].volume = companies[_companyId].volume + msg.value;
    }

    /*
    This function is used to handle the purchase of a share.
    */
    function purchaseShare(uint _shareId) public payable {
        require(msg.value == shares[_shareId].curPrice);
    
        uint256 commission1percent = (msg.value / 100);
        /*
        We check if this is the first purchase of a share or a "repurchase".
        If it's the first purchase we transfer a larger commission to the company owner
        */
        if(shares[_shareId].ownerAddress == cfoAddress) {
            // This is the initial sale
            companies[shares[_shareId].companyId].ownerAddress.transfer(commission1percent * 80); // 80% goes to the company owner
            cfoAddress.transfer(commission1percent * 20);    // 20% goes to the dev
        } else {
            // This is a consecutive sale
            shares[_shareId].ownerAddress.transfer(commission1percent * 85);    // 85% goes to the previous shareholder
            companies[shares[_shareId].companyId].ownerAddress.transfer(commission1percent * 10); // 10% goes to the company owner
            cfoAddress.transfer(commission1percent * 5);    // 5% goes to the dev
        }
        // Decrement count shares previous user
        addressSharesCount[shares[_shareId].ownerAddress]--;
        
        // Update the owner of the share
        shares[_shareId].ownerAddress = msg.sender;
        addressSharesCount[msg.sender]++;
        
        // Raise the price of the share
        shares[_shareId].curPrice = shares[_shareId].curPrice + (shares[_shareId].curPrice / 2);
        
        // Increment volume generated by company
        companies[shares[_shareId].companyId].volume = companies[shares[_shareId].companyId].volume + msg.value;
    }

    // This function will return an array of addresses of the company shareholders (very useful to transfer their ad commission)
    function getCompanyShareholders(uint _companyId) public view returns(address[]) {
        address[] memory result = new address[](5);
        uint counter = 0;
        for (uint i = 0; i < shares.length; i++) {
          if (shares[i].companyId == _companyId) {
            result[counter] = shares[i].ownerAddress;
            counter++;
          }
        }
        return result;
    }

    /*
    The owner of a company can reduce the price of the company using this function.
    The price can be reduced but cannot be bigger.
    The price is set in WEI.
    */
    function updateCompanyPrice(uint _companyId, uint256 _newPrice) public {
        require(_newPrice > 0);
        require(companies[_companyId].ownerAddress == msg.sender);
        require(_newPrice < companies[_companyId].curPrice);
        companies[_companyId].curPrice = _newPrice;
    }
    
    /*
    The owner of a share can reduce the price of the selected share using this function.
    The price of the share can be reduced but cannot be bigger.
    The price is set in WEI.
    */
    function updateSharePrice(uint _shareId, uint256 _newPrice) public {
        require(_newPrice > 0);
        require(shares[_shareId].ownerAddress == msg.sender);
        require(_newPrice < shares[_shareId].curPrice);
        shares[_shareId].curPrice = _newPrice;
    }
    
    // This function will return the details of a company
    function getCompany(uint _companyId) public view returns (
        string name,
        address ownerAddress,
        uint256 curPrice,
        uint256 curAdPrice,
        string curAdText,
        string curAdLink,
        uint shareId,   // The id of the least expensive share of this company
        uint256 sharePrice,  // The price of the least expensive share of this company
        uint256 volume
    ) {
        Company storage _company = companies[_companyId];

        name = _company.name;
        ownerAddress = _company.ownerAddress;
        curPrice = _company.curPrice;
        curAdPrice = _company.curAdPrice;
        curAdText = _company.curAdText;
        curAdLink = _company.curAdLink;
        shareId = getLeastExpensiveShare(_companyId,0);
        sharePrice = getLeastExpensiveShare(_companyId,1);
        volume = _company.volume;
    }

    // This function will return the details of a share
    function getShare(uint _shareId) public view returns (
        uint companyId,
        address ownerAddress,
        uint256 curPrice
    ) {
        Share storage _share = shares[_shareId];

        companyId = _share.companyId;
        ownerAddress = _share.ownerAddress;
        curPrice = _share.curPrice;
    }
    
    /*
    This function will return the shares owned by the sender.
    */
    function getMyShares() public view returns(uint[]) {
        uint[] memory result = new uint[](addressSharesCount[msg.sender]);
        uint counter = 0;
        for (uint i = 0; i < shares.length; i++) {
          if (shares[i].ownerAddress == msg.sender) {
            result[counter] = i;
            counter++;
          }
        }
        return result;
    }
    
    // Get least expensive share of one company
    function getLeastExpensiveShare(uint _companyId, uint _type) public view returns(uint) {
        uint _shareId = 0;
        uint256 _sharePrice = 999000000000000000000;

        // Loop through all the shares of this company
        for (uint8 i = 0; i < shares.length; i++) {
            // Get only the shares of this company
            if(shares[i].companyId == _companyId) {
                // Check if this share is less expensive than the previous and if it's not already owned by the connected user
                if(shares[i].curPrice < _sharePrice && shares[i].ownerAddress != msg.sender) {
                    _sharePrice = shares[i].curPrice;
                    _shareId = i;
                }
            }
        }

        // Return the price or the id of the company's least expensive share
        if(_type == 0) {
            return(_shareId);
        } else {
            return(_sharePrice);
        }
    }
    
    /**
    @dev Multiplies two numbers, throws on overflow. => From the SafeMath library
    */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
          return 0;
        }
        uint256 c = a * b;
        assert(c / a == b);
        return c;
    }

    /**
    @dev Integer division of two numbers, truncating the quotient. => From the SafeMath library
    */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        // assert(b > 0); // Solidity automatically throws when dividing by 0
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold
        return c;
    }
    
    // The dev can use this function to create new companies.
    function createCompany(string _companyName, uint256 _companyPrice) public onlyCeo {
        uint companyId = companies.push(Company(_companyName, cfoAddress, _companyPrice, 10000000000000000, "0", "#",0, 0, 0)) - 1;
        // The initial price of a share is always the initial price of a company / 10.
        uint256 sharePrice = _companyPrice / 10;
        
        // We create 5 shares for this company
        shares.push(Share(companyId, cfoAddress, sharePrice));
        shares.push(Share(companyId, cfoAddress, sharePrice));
        shares.push(Share(companyId, cfoAddress, sharePrice));
        shares.push(Share(companyId, cfoAddress, sharePrice));
        shares.push(Share(companyId, cfoAddress, sharePrice));
    }
    
    // Initiate functions that will create the companies
    function InitiateCompanies() public onlyCeo {
        require(companiesAreInitiated == false);
        createCompany("Apple", 350000000000000000); 
        createCompany("Snapchat", 200000000000000000); 
        createCompany("Facebook", 250000000000000000); 
        createCompany("Google", 250000000000000000); 
        createCompany("Microsoft", 350000000000000000); 
        createCompany("Nintendo", 150000000000000000); 
        createCompany("Mc Donald", 250000000000000000); 
        createCompany("Kodak", 100000000000000000);
        createCompany("Twitter", 100000000000000000);

    }
}
