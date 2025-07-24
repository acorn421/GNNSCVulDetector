/*
 * ===== SmartInject Injection Details =====
 * Function      : modifyCurrentVideoGameItemPrice
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability where price modification limits depend on block.timestamp parity. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **State Persistence**: Added lastPriceModification timestamp storage to VideoGameItem struct (requires struct modification)
 * 2. **Timestamp Logic**: Price reduction limits change based on whether block.timestamp is even or odd
 * 3. **Multi-Transaction Exploitation**: 
 *    - Transaction 1: Owner attempts price modification during restrictive period (odd timestamp) with limited reduction
 *    - Attacker/Miner manipulation: Wait for or manipulate timestamp to be even
 *    - Transaction 2: Owner can now reduce price by up to 50% instead of 20%
 *    - Transaction 3: Potential purchase at artificially low price
 * 
 * **Exploitation Scenario**:
 * - **Transaction 1**: Owner calls function when block.timestamp is odd, can only reduce price by 20%
 * - **Time passage/manipulation**: Block timestamp becomes even (miners can influence this within ~15 second window)
 * - **Transaction 2**: Owner calls function again with same item, now can reduce price by 50% due to timestamp parity
 * - **Transaction 3**: Attacker purchases item at deeply discounted price
 * 
 * **Why Multi-Transaction**:
 * - Requires separate transactions to take advantage of timestamp changes
 * - State (lastPriceModification) persists between calls
 * - Cannot be exploited atomically in single transaction
 * - Timing dependency creates window for manipulation between transactions
 * 
 * **Realistic Vulnerability**: Mimics real-world trading systems with time-based market rules, making the timestamp dependence appear legitimate while being exploitable through miner timestamp manipulation.
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
        uint256 lastPriceModification; // Added to allow timestamp recording
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Timestamp-dependent vulnerability: Use block.timestamp for critical price modification logic
        // Allow deeper price reductions during "market hours" (simulated as even-numbered timestamps)
        uint256 maxReductionPercent;
        if (block.timestamp % 2 == 0) {
            // During "market hours" - allow up to 50% reduction
            maxReductionPercent = 50;
        } else {
            // During "off hours" - allow up to 20% reduction
            maxReductionPercent = 20;
        }
        
        // Store the timestamp when price was last modified (stateful component)
        videoGameItems[_videoGameItemId].lastPriceModification = block.timestamp;
        
        // Calculate minimum allowed price based on timestamp-dependent reduction
        uint256 currentPrice = videoGameItems[_videoGameItemId].currentPrice;
        uint256 minAllowedPrice = currentPrice - (currentPrice * maxReductionPercent / 100);
        
        // Vulnerability: Price reduction limit depends on manipulatable block.timestamp
        require(_newPrice >= minAllowedPrice);
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
