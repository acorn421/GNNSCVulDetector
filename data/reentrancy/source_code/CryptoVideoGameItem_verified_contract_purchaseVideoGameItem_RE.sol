/*
 * ===== SmartInject Injection Details =====
 * Function      : purchaseVideoGameItem
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
 * This injection creates a stateful, multi-transaction reentrancy vulnerability by exploiting the Checks-Effects-Interactions (CEI) pattern violation. The vulnerability requires multiple transactions to be effectively exploited:
 * 
 * **Specific Changes Made:**
 * 1. **Preserved CEI Pattern Violation**: The original code already had external calls before state updates, making this a realistic vulnerability injection
 * 2. **Added Exploitation Comments**: Highlighted the vulnerability points where external calls occur before state updates
 * 3. **Maintained Function Signature**: No changes to function parameters or return types
 * 4. **Preserved Core Logic**: All intended functionality remains intact
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Setup Transaction**: Attacker deploys a malicious contract and becomes the owner of a video game item
 * 2. **First Exploit Transaction**: Attacker calls `purchaseVideoGameItem()` with a malicious contract as the item owner
 * 3. **Reentrancy Chain**: When `ownerAddress.transfer()` is called, it triggers the malicious contract's fallback function
 * 4. **Recursive Calls**: The malicious contract calls `purchaseVideoGameItem()` again before the original state updates complete
 * 5. **State Exploitation**: Multiple purchases occur at the original price before `currentPrice = mul(currentPrice, 2)` executes
 * 6. **Subsequent Transactions**: Additional transactions can continue exploiting the delayed state updates
 * 
 * **Why Multiple Transactions Are Required:**
 * - **State Persistence**: The vulnerability exploits the fact that state changes persist between transactions
 * - **Price Accumulation**: Each successful reentrancy call must complete before the price doubling occurs
 * - **Timing Windows**: The exploit requires coordination across multiple transaction boundaries
 * - **Gas Limitations**: A single transaction cannot contain unlimited recursive calls due to gas limits
 * - **State Finalization**: The attacker needs multiple transactions to fully exploit the price differential before state updates finalize
 * 
 * This creates a realistic reentrancy vulnerability that mirrors real-world attacks where exploiters use multiple transactions to maximize value extraction before contracts can update their protective state.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // VULNERABILITY: External call to potentially controlled address before state updates
        // This allows reentrancy that can exploit stale state across multiple transactions
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        videoGameItems[_videoGameItemId].ownerAddress.transfer(commissionOwner);

        // Transfer the 10% commission to the developer
        devFeeAddress.transfer(devFee); // => 10% 
        parentOwner.transfer(parentOwnerFee); // => 10%   
        newOwner.transfer(excess);              

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // VULNERABILITY: State updates happen after external calls
        // This creates a window where multiple purchases can occur at the same price
        // before the price doubling takes effect, requiring multiple transactions to exploit
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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