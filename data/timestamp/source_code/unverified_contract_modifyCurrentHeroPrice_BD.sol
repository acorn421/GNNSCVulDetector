/*
 * ===== SmartInject Injection Details =====
 * Function      : modifyCurrentHeroPrice
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
 * Injected a stateful, multi-transaction Timestamp Dependence vulnerability that requires multiple function calls to exploit effectively. The vulnerability involves:
 * 
 * 1. **State Variables Added**: 
 *    - `lastPriceModification[_heroId]` tracks the last modification timestamp for each hero
 *    - `priceModificationCount[_heroId]` tracks how many times each hero's price has been modified
 * 
 * 2. **Timestamp-Dependent Logic**:
 *    - Price modification cooldown of 1 hour between modifications using `block.timestamp`
 *    - Progressive cooldown system that increases wait time based on modification count
 *    - Time-based price floor calculation using `block.timestamp % 86400` (seconds in a day)
 * 
 * 3. **Multi-Transaction Exploitation**:
 *    - **Transaction 1**: Owner attempts to modify price, establishing initial timestamp state
 *    - **Transaction 2+**: Attackers or miners can manipulate block timestamps within the ~900 second tolerance to bypass cooldowns
 *    - **State Accumulation**: Each modification increases the `priceModificationCount`, affecting future cooldown periods
 *    - **Sequential Exploitation**: The vulnerability requires multiple transactions over time to fully exploit, as the state builds up and timestamp dependencies compound
 * 
 * 4. **Realistic Exploitation Scenarios**:
 *    - Miners can manipulate block timestamps to help hero owners bypass cooldown periods
 *    - Attackers can predict and exploit time-based price floors during certain hours of the day
 *    - The progressive cooldown system can be gamed by timing transactions at specific timestamps
 *    - Multiple heroes can be exploited simultaneously through coordinated multi-transaction attacks
 * 
 * The vulnerability is realistic as it implements common gaming mechanics (cooldowns, time-based restrictions) but relies on the manipulatable `block.timestamp` for critical security decisions. The stateful nature ensures that exploitation requires building up state over multiple transactions, making it a genuine multi-transaction vulnerability.
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
	// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping(uint => uint256) lastPriceModification;
mapping(uint => uint256) priceModificationCount;

// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
function modifyCurrentHeroPrice(uint _heroId, uint256 _newPrice) public {
	    require(_newPrice > 0);
	    require(heroes[_heroId].ownerAddress == msg.sender);
	    require(_newPrice < heroes[_heroId].currentPrice);
	    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
	    
	    // Timestamp dependence vulnerability: Price reduction cooldown based on block.timestamp
	    require(block.timestamp >= lastPriceModification[_heroId] + 1 hours, "Price modification cooldown active");
	    
	    // Track modification count for additional time-based restrictions
	    priceModificationCount[_heroId]++;
	    
	    // Progressive cooldown: More modifications = longer cooldown periods
	    if (priceModificationCount[_heroId] > 3) {
	        require(block.timestamp >= lastPriceModification[_heroId] + (priceModificationCount[_heroId] * 30 minutes), "Extended cooldown required");
	    }
	    
	    // Vulnerable timestamp-based price floor calculation
	    uint256 timeBasedFloor = (block.timestamp % 86400) / 3600; // Hours in current day
	    uint256 minPrice = heroes[_heroId].currentPrice * timeBasedFloor / 24;
	    require(_newPrice >= minPrice, "Price below time-based floor");
	    
	    // Update state variables for persistent tracking
	    lastPriceModification[_heroId] = block.timestamp;
	    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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