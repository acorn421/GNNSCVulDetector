/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleAuction
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
 * This vulnerability introduces timestamp dependence in auction scheduling and bidding. The contract uses block.timestamp for time-sensitive operations, which can be manipulated by miners within a 900-second window. This creates a multi-transaction vulnerability where: 1) An auction is scheduled using block.timestamp, 2) Bidders place bids based on timestamp checks, 3) The auction is finalized based on timestamp validation. Miners can manipulate timestamps to extend bidding periods, prevent timely finalization, or gain unfair advantages in the auction process. The vulnerability requires multiple transactions (schedule → bid → finalize) and maintains state between transactions through the auction struct.
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
    }
    VideoGameItem[] videoGameItems;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    struct Auction {
        uint256 itemId;
        uint256 startTime;
        uint256 duration;
        uint256 startingPrice;
        uint256 highestBid;
        address highestBidder;
        bool active;
        bool ended;
    }
    
    mapping(uint256 => Auction) public auctions;
    uint256 public auctionCounter;
    
    function scheduleAuction(uint256 _itemId, uint256 _duration, uint256 _startingPrice) public {
        require(videoGameItems[_itemId].ownerAddress == msg.sender);
        require(_duration > 0);
        require(_startingPrice > 0);
        
        // Vulnerable: Using block.timestamp for time-dependent operations
        // Miners can manipulate timestamp within limits
        uint256 startTime = block.timestamp + 300; // 5 minutes from now
        
        auctions[auctionCounter] = Auction({
            itemId: _itemId,
            startTime: startTime,
            duration: _duration,
            startingPrice: _startingPrice,
            highestBid: 0,
            highestBidder: address(0),
            active: true,
            ended: false
        });
        
        auctionCounter++;
    }
    
    function placeBid(uint256 _auctionId) public payable {
        Auction storage auction = auctions[_auctionId];
        require(auction.active);
        require(!auction.ended);
        
        // Vulnerable: Time-dependent logic using block.timestamp
        // Miners can manipulate this within a 900-second window
        require(block.timestamp >= auction.startTime);
        require(block.timestamp <= auction.startTime + auction.duration);
        
        require(msg.value > auction.highestBid);
        require(msg.value >= auction.startingPrice);
        
        // Refund previous highest bidder
        if (auction.highestBidder != address(0)) {
            auction.highestBidder.transfer(auction.highestBid);
        }
        
        auction.highestBid = msg.value;
        auction.highestBidder = msg.sender;
    }
    
    function finalizeAuction(uint256 _auctionId) public {
        Auction storage auction = auctions[_auctionId];
        require(auction.active);
        require(!auction.ended);
        
        // Vulnerable: Time-dependent finalization
        // Miners can delay finalization by manipulating timestamp
        require(block.timestamp > auction.startTime + auction.duration);
        
        auction.ended = true;
        auction.active = false;
        
        if (auction.highestBidder != address(0)) {
            // Transfer item ownership
            videoGameItems[auction.itemId].ownerAddress = auction.highestBidder;
            
            // Calculate fees
            uint256 devFee = auction.highestBid / 10;
            uint256 ownerPayout = auction.highestBid - devFee;
            
            // Transfer payments
            devFeeAddress.transfer(devFee);
            msg.sender.transfer(ownerPayout);
        }
    }
    // === END FALLBACK INJECTION ===


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
        uint256 excess = msg.value - currentPrice;
        // Calculate the 10% value
        uint256 devFee = (currentPrice / 10);
        uint256 parentOwnerFee = (currentPrice / 10);

        address parentOwner = parentContract.getVideoGameOwner(videoGameItems[_videoGameItemId].parentVideoGame);
        address newOwner = msg.sender;
        // Calculate the video game owner commission on this sale & transfer the commission to the owner.     
        uint256 commissionOwner = currentPrice - devFee - parentOwnerFee; // => 80%
        videoGameItems[_videoGameItemId].ownerAddress.transfer(commissionOwner);

        // Transfer the 10% commission to the developer
        devFeeAddress.transfer(devFee); // => 10% 
        parentOwner.transfer(parentOwnerFee); // => 10%   
        newOwner.transfer(excess);              

        // Update the video game owner and set the new price
        videoGameItems[_videoGameItemId].ownerAddress = newOwner;
        videoGameItems[_videoGameItemId].currentPrice = mul(videoGameItems[_videoGameItemId].currentPrice, 2);
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
        videoGameItems.push(VideoGameItem(videoGameItemName,ownerAddress,currentPrice, parentVideoGame));
    }
    
}



contract CryptoVideoGames {
    
    
    
    // This function will return only the owner address of a specific Video Game
    function getVideoGameOwner(uint _videoGameId) public view returns(address) {
    }
    
}
