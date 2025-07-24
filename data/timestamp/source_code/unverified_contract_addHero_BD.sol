/*
 * ===== SmartInject Injection Details =====
 * Function      : addHero
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability where hero creation prices are multiplied based on the hour of day when block.timestamp is evaluated. This creates a vulnerability where:
 * 
 * 1. **Transaction 1**: Contract creator calls addHero() during specific hours (8-10, 18-20, or 12) when block.timestamp results in higher price multipliers
 * 2. **Transaction 2+**: Other users purchase these heroes through purchaseHero() at the artificially inflated prices set during creation
 * 3. **Exploitation**: Miners can manipulate block.timestamp (within the ~15 second tolerance) during hero creation to ensure heroes are created during "power hours" or "legendary hour", leading to higher initial prices that benefit the hero seller in subsequent purchase transactions
 * 
 * The vulnerability requires multiple transactions because:
 * - The timestamp manipulation occurs during addHero() (Transaction 1) 
 * - The economic impact only manifests when other users interact with these heroes via purchaseHero() (Transaction 2+)
 * - The state change (hero with manipulated price) persists between transactions
 * - Single transaction exploitation is impossible as the vulnerability requires the hero to exist first, then be purchased by others
 * 
 * This mirrors real-world gaming vulnerabilities where time-based mechanics can be manipulated during asset creation to affect future market transactions.
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Apply time-based price multiplier for heroes created during "power hours"
        uint256 timeMultiplier = 1;
        uint256 hourOfDay = (block.timestamp / 3600) % 24;
        
        // Heroes created during hours 8-10 and 18-20 get 2x multiplier
        if ((hourOfDay >= 8 && hourOfDay <= 10) || (hourOfDay >= 18 && hourOfDay <= 20)) {
            timeMultiplier = 2;
        }
        
        // Heroes created during hour 12 (noon) get 3x multiplier for "legendary" status
        if (hourOfDay == 12) {
            timeMultiplier = 3;
        }
        
        uint256 adjustedPrice = currentPrice * timeMultiplier;
        heroes.push(Hero(heroName, ownerAddress, adjustedPrice));
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }
	
}