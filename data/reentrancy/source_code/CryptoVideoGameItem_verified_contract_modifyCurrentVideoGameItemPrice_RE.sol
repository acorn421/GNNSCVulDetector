/*
 * ===== SmartInject Injection Details =====
 * Function      : modifyCurrentVideoGameItemPrice
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
 * 2. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the owner's contract before the state update. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `ownerAddress.call()` with `onPriceModified` callback before state update
 * 2. Stored `oldPrice` to pass to callback, creating intermediate state
 * 3. Moved state update (`videoGameItems[_videoGameItemId].currentPrice = _newPrice`) to after external call
 * 4. Added realistic justification (price aggregator notification) for the external call
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Setup Phase (Transaction 1)**: Attacker deploys a malicious contract and becomes owner of a video game item
 * 2. **Exploitation Phase (Transaction 2)**: Attacker calls `modifyCurrentVideoGameItemPrice` with their malicious contract as owner
 * 3. **Reentrancy Trigger**: During the `onPriceModified` callback, the malicious contract re-enters `modifyCurrentVideoGameItemPrice`
 * 4. **State Manipulation**: The re-entrant call sees the old price state, allowing multiple price modifications in unexpected ways
 * 5. **Accumulation Effect**: Each transaction builds on the state changes from previous transactions, allowing complex manipulation patterns
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the attacker to first become the owner (separate transaction)
 * - The malicious contract must be deployed and configured beforehand
 * - The reentrancy creates a sequence where intermediate states from previous calls enable further exploitation
 * - Multiple calls can accumulate effects that wouldn't be possible in a single transaction
 * - The attacker can chain multiple price modifications by exploiting the state inconsistency across transaction boundaries
 * 
 * **Realistic Vulnerability Pattern:**
 * This follows the classic Checks-Effects-Interactions pattern violation where an external call occurs before state updates, creating a window for reentrancy. The price notification callback is a realistic feature that could legitimately exist in a marketplace system, making this vulnerability subtle and production-like.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Track price change for marketplace integration
        uint256 oldPrice = videoGameItems[_videoGameItemId].currentPrice;
        
        // Notify external price aggregator service before state update
        address ownerAddress = videoGameItems[_videoGameItemId].ownerAddress;
        if (isContract(ownerAddress)) {
            // External call to owner contract for price change notification
            ownerAddress.call(
                bytes4(keccak256("onPriceModified(uint256,uint256,uint256)")), 
                _videoGameItemId, oldPrice, _newPrice
            );
            // Continue execution regardless of callback success
        }
        
        // State update happens after external call - VULNERABILITY
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

    // Helper function to check if an address is a contract (for Solidity 0.4.18)
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
    
}



contract CryptoVideoGames {
    
    
    
    // This function will return only the owner address of a specific Video Game
    function getVideoGameOwner(uint _videoGameId) public view returns(address) {
    }
    
}
