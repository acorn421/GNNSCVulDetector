/*
 * ===== SmartInject Injection Details =====
 * Function      : purchaseVideoGameItem
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through a time-based discount system. The vulnerability allows miners to manipulate block timestamps to repeatedly trigger favorable discount conditions across multiple transactions. The system stores the last purchase timestamp in state and applies progressive discounts based on time elapsed since the last purchase, creating opportunities for timestamp manipulation attacks that require multiple coordinated transactions to maximize profit extraction.
 */
pragma solidity ^0.4.18;

contract CryptoVideoGameItem {

    address contractCreator = 0xC15d9f97aC926a6A29A681f5c19e2b56fd208f00; 
    address devFeeAddress = 0xC15d9f97aC926a6A29A681f5c19e2b56fd208f00;

    address cryptoVideoGames = 0xdEc14D8f4DA25108Fd0d32Bf2DeCD9538564D069; 

    struct VideoGameItem {
        string videoGameItemName;
        address ownerAddress;
        uint256 currentPrice;
        uint parentVideoGame;
        uint256 lastPurchaseTime;
    }
    VideoGameItem[] videoGameItems;

    modifier onlyContractCreator() {
        require (msg.sender == contractCreator);
        _;
    }

    bool isPaused;
    
    
    /*
    We use the following functions to pause and unpause the game.
    */
    function pauseGame() public onlyContractCreator {
        isPaused = true;
    }
    function unPauseGame() public onlyContractCreator {
        isPaused = false;
    }
    function GetGamestatus() public view returns(bool) {
       return(isPaused);
    }

    /*
    This function allows users to purchase Video Game Item. 
    The price is automatically multiplied by 2 after each purchase.
    Users can purchase multiple video game Items.
    */
    function purchaseVideoGameItem(uint _videoGameItemId) public payable {
        require(msg.value >= videoGameItems[_videoGameItemId].currentPrice);
        require(isPaused == false);

        CryptoVideoGames parentContract = CryptoVideoGames(cryptoVideoGames);
        uint256 currentPrice = videoGameItems[_videoGameItemId].currentPrice;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based discount system vulnerable to timestamp manipulation
        uint256 timeSinceLastPurchase = block.timestamp - videoGameItems[_videoGameItemId].lastPurchaseTime;
        uint256 discountMultiplier = 100; // Default 100% (no discount)
        
        // Apply progressive discount based on time elapsed
        if (timeSinceLastPurchase >= 1 hours) {
            discountMultiplier = 90; // 10% discount after 1 hour
        }
        if (timeSinceLastPurchase >= 6 hours) {
            discountMultiplier = 80; // 20% discount after 6 hours
        }
        if (timeSinceLastPurchase >= 24 hours) {
            discountMultiplier = 70; // 30% discount after 24 hours
        }
        
        // Calculate discounted price using timestamp-dependent logic
        uint256 discountedPrice = (currentPrice * discountMultiplier) / 100;
        require(msg.value >= discountedPrice);
        
        uint256 excess = msg.value - discountedPrice;
        // Calculate the 10% value based on discounted price
        uint256 devFee = (discountedPrice / 10);
        uint256 parentOwnerFee = (discountedPrice / 10);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

        address parentOwner = parentContract.getVideoGameOwner(videoGameItems[_videoGameItemId].parentVideoGame);
        address newOwner = msg.sender;
        // Calculate the video game owner commission on this sale & transfer the commission to the owner.     
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        uint256 commissionOwner = discountedPrice - devFee - parentOwnerFee; // => 80%
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        videoGameItems[_videoGameItemId].ownerAddress.transfer(commissionOwner);

        // Transfer the 10% commission to the developer
        devFeeAddress.transfer(devFee); // => 10% 
        parentOwner.transfer(parentOwnerFee); // => 10%   
        newOwner.transfer(excess);              

        // Update the video game owner and set the new price
        videoGameItems[_videoGameItemId].ownerAddress = newOwner;
        videoGameItems[_videoGameItemId].currentPrice = mul(videoGameItems[_videoGameItemId].currentPrice, 2);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Store timestamp for next purchase discount calculation
        videoGameItems[_videoGameItemId].lastPurchaseTime = block.timestamp;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }
    
    /*
    This function can be used by the owner of a video game item to modify the price of its video game item.
    He can make the price lesser than the current price only.
    */
    function modifyCurrentVideoGameItemPrice(uint _videoGameItemId, uint256 _newPrice) public {
        require(_newPrice > 0);
        require(videoGameItems[_videoGameItemId].ownerAddress == msg.sender);
        require(_newPrice < videoGameItems[_videoGameItemId].currentPrice);
        videoGameItems[_videoGameItemId].currentPrice = _newPrice;
    }
    
    // This function will return all of the details of the Video Game Item
    function getVideoGameItemDetails(uint _videoGameItemId) public view returns (
        string videoGameItemName,
        address ownerAddress,
        uint256 currentPrice,
        uint parentVideoGame
    ) {
        VideoGameItem memory _videoGameItem = videoGameItems[_videoGameItemId];

        videoGameItemName = _videoGameItem.videoGameItemName;
        ownerAddress = _videoGameItem.ownerAddress;
        currentPrice = _videoGameItem.currentPrice;
        parentVideoGame = _videoGameItem.parentVideoGame;
    }
    
    // This function will return only the price of a specific Video Game Item
    function getVideoGameItemCurrentPrice(uint _videoGameItemId) public view returns(uint256) {
        return(videoGameItems[_videoGameItemId].currentPrice);
    }
    
    // This function will return only the owner address of a specific Video Game
    function getVideoGameItemOwner(uint _videoGameItemId) public view returns(address) {
        return(videoGameItems[_videoGameItemId].ownerAddress);
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
    
    // This function will be used to add a new video game by the contract creator
    function addVideoGameItem(string videoGameItemName, address ownerAddress, uint256 currentPrice, uint parentVideoGame) public onlyContractCreator {
        videoGameItems.push(VideoGameItem(videoGameItemName,ownerAddress,currentPrice, parentVideoGame, 0));
    }
    
}



contract CryptoVideoGames {
    
    
    
    // This function will return only the owner address of a specific Video Game
    function getVideoGameOwner(uint _videoGameId) public view returns(address) {
    }
    
}
