/*
 * ===== SmartInject Injection Details =====
 * Function      : purchaseCompany
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * Injected a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added Withdrawal Pattern**: Introduced a `pendingWithdrawals` mapping that accumulates commissions over multiple transactions instead of immediately transferring funds.
 * 
 * 2. **External Call Before State Updates**: Added an external call to the previous owner's contract using `call.value(0)()` to notify of the purchase. This call happens before critical state updates (ownership transfer, price update).
 * 
 * 3. **State Accumulation**: The `pendingWithdrawals` mapping allows commissions to accumulate across multiple purchases, creating a stateful vulnerability that depends on previous transaction history.
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * **Transaction 1**: Attacker purchases Company A
 * - Commissions accumulate in `pendingWithdrawals`
 * - External call to previous owner triggers reentrancy
 * - During reentrancy, attacker can observe that ownership hasn't changed yet
 * - Attacker can purchase Company B while still appearing as non-owner
 * 
 * **Transaction 2**: Attacker calls a withdrawal function (assumed to exist)
 * - Withdraws accumulated commissions from multiple purchases
 * - The vulnerability exists because state updates happen after external calls
 * 
 * **Transaction 3+**: Repeat the process
 * - Each purchase adds to accumulated state
 * - Reentrancy allows manipulation of the purchase flow
 * - Multiple transactions build up exploitable state
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability depends on accumulated `pendingWithdrawals` state from previous transactions
 * - Each purchase builds up the attacker's potential withdrawal amount
 * - The reentrancy allows the attacker to make multiple purchases before ownership state is properly updated
 * - A single transaction cannot accumulate sufficient state to make the exploit profitable
 * 
 * The vulnerability is realistic because it mimics real-world patterns where contracts use withdrawal patterns and external notifications, both of which are legitimate design patterns that can introduce reentrancy when not properly implemented.
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
    
    // Add declaration for pendingWithdrawals
    mapping(address => uint256) public pendingWithdrawals;
    
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

        // Calculate the 5% value
        uint256 commission5percent = ((msg.value / 10)/2);

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Calculate the owner commission on this sale
        uint256 commissionOwner = msg.value - commission5percent; // => 95%
        
        // Add commission to pending withdrawals for the owner
        pendingWithdrawals[companies[_companyId].ownerAddress] += commissionOwner;
        
        // Add commission to pending withdrawals for the developer
        pendingWithdrawals[cfoAddress] += commission5percent;
        
        // Call external contract to notify of purchase (potential reentrancy point)
        if (companies[_companyId].ownerAddress.call.value(0)(bytes4(keccak256("onCompanyPurchased(uint256,address,uint256)")), _companyId, msg.sender, msg.value)) {
            // External call succeeded - continue with purchase
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        // Update the company owner and set the new price
        companies[_companyId].ownerAddress = msg.sender;
        companies[_companyId].curPrice = companies[_companyId].curPrice + (companies[_companyId].curPrice / 2);
        
        // Increment volume generated by company
        companies[_companyId].volume = companies[_companyId].volume + msg.value;
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
        uint companyId = companies.push(Company(_companyName, cfoAddress, _companyPrice, 10000000000000000, "0", "#",0)) - 1;
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