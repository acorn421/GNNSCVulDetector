/*
 * ===== SmartInject Injection Details =====
 * Function      : modifyCurrentHeroPrice
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
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a price change notifier before the state update. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `IPriceNotifier(priceChangeNotifier).notifyPriceChange()` before state update
 * 2. The external call passes current price and new price, allowing the malicious contract to see the intended change
 * 3. State update (`heroes[_heroId].currentPrice = _newPrice`) happens AFTER the external call
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1**: Attacker (hero owner) calls `modifyCurrentHeroPrice(heroId, lowerPrice)` to legitimately reduce price
 * 2. **During TX1**: External call to malicious notifier contract triggers reentrancy
 * 3. **Reentrant Call**: Malicious contract calls `modifyCurrentHeroPrice(heroId, evenLowerPrice)` again
 * 4. **State Confusion**: The reentrant call sees the OLD price in requires but the state gets updated multiple times
 * 5. **Transaction 2+**: Subsequent legitimate transactions operate on manipulated state
 * 
 * **Why Multi-Transaction Required:**
 * - The attack requires the hero owner to first legitimately call the function (Transaction 1)
 * - The malicious contract must be set as the priceChangeNotifier through separate transactions
 * - The accumulated state changes from reentrancy affect future price modifications
 * - The exploit leverages the persistent state changes that remain after the initial transaction completes
 * 
 * **Realistic Vulnerability Context:**
 * - The price change notifier could be a legitimate marketplace integration
 * - The external call appears necessary for proper system integration
 * - The vulnerability is subtle and could easily be missed in code reviews
 * - The state changes accumulate across multiple transactions, creating lasting impact
 */
pragma solidity ^0.4.18;

/*
Game: Dragon Ball Z
Domain: EtherDragonBall.com
*/

contract DragonBallZ {

	address contractCreator = 0x23B385c822381BE63C9f45a3E45266DD32D52c43;
    address devFeeAddress = 0x3bdC0D871731D08D1c1c793735372AB16397Cd61;

	struct Hero {
		string heroName;
		address ownerAddress;
		uint256 currentPrice;
	}
	Hero[] heroes;

    // Added declaration for priceChangeNotifier
    address public priceChangeNotifier;

    // Moved IPriceNotifier definition outside contract as required in Solidity 0.4.x
}

interface IPriceNotifier {
    function notifyPriceChange(uint _heroId, uint256 oldPrice, uint256 newPrice) external;
}

contract DragonBallZV2 is DragonBallZ {
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
    This function allows users to purchase Dragon Ball Z hero. 
    The price is automatically multiplied by 2 after each purchase.
    Users can purchase multiple heroes.
    */
	function purchaseHero(uint _heroId) public payable {
		require(msg.value == heroes[_heroId].currentPrice);
		require(isPaused == false);

		// Calculate the 10% value
		uint256 devFee = (msg.value / 10);

		// Calculate the hero owner commission on this sale & transfer the commission to the owner. 		
		uint256 commissionOwner = msg.value - devFee; // => 90%
		heroes[_heroId].ownerAddress.transfer(commissionOwner);

		// Transfer the 10% commission to the developer
		devFeeAddress.transfer(devFee); // => 10% 						

		// Update the hero owner and set the new price
		heroes[_heroId].ownerAddress = msg.sender;
		heroes[_heroId].currentPrice = mul(heroes[_heroId].currentPrice, 2);
	}
	
	/*
	This function can be used by the owner of a hero to modify the price of its hero.
	He can make the price lesser than the current price only.
	*/
	function modifyCurrentHeroPrice(uint _heroId, uint256 _newPrice) public {
	    require(_newPrice > 0);
	    require(heroes[_heroId].ownerAddress == msg.sender);
	    require(_newPrice < heroes[_heroId].currentPrice);
	    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
	    
	    // Price change notification - external call before state update
	    if (priceChangeNotifier != address(0)) {
	        IPriceNotifier(priceChangeNotifier).notifyPriceChange(_heroId, heroes[_heroId].currentPrice, _newPrice);
	    }
	    
	    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
	    heroes[_heroId].currentPrice = _newPrice;
	}
	
	// This function will return all of the details of the Dragon Ball Z heroes
	function getHeroDetails(uint _heroId) public view returns (
        string heroName,
        address ownerAddress,
        uint256 currentPrice
    ) {
        Hero storage _hero = heroes[_heroId];

        heroName = _hero.heroName;
        ownerAddress = _hero.ownerAddress;
        currentPrice = _hero.currentPrice;
    }
    
    // This function will return only the price of a specific hero
    function getHeroCurrentPrice(uint _heroId) public view returns(uint256) {
        return(heroes[_heroId].currentPrice);
    }
    
    // This function will return only the owner address of a specific hero
    function getHeroOwner(uint _heroId) public view returns(address) {
        return(heroes[_heroId].ownerAddress);
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
    
	// This function will be used to add a new hero by the contract creator
	function addHero(string heroName, address ownerAddress, uint256 currentPrice) public onlyContractCreator {
        heroes.push(Hero(heroName,ownerAddress,currentPrice));
    }
	
}
