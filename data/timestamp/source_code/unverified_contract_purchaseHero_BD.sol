/*
 * ===== SmartInject Injection Details =====
 * Function      : purchaseHero
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
 * **SPECIFIC CHANGES MADE:**
 * 
 * 1. **Added timestamp-based pricing logic**: The function now calculates a time-based discount where hero prices decrease by 5% per hour since the last purchase, with a maximum discount of 50%.
 * 
 * 2. **Introduced block.timestamp dependency**: The pricing calculation directly depends on `block.timestamp` and the stored `lastPurchaseTime` state variable.
 * 
 * 3. **Added persistent timestamp storage**: The function now updates `heroes[_heroId].lastPurchaseTime = block.timestamp` at the end, creating persistent state that affects future transactions.
 * 
 * 4. **Modified price requirement**: Instead of requiring the exact `currentPrice`, the function now requires payment of the calculated `discountedPrice` based on time elapsed.
 * 
 * **MULTI-TRANSACTION EXPLOITATION SCENARIO:**
 * 
 * **Transaction 1 (Setup)**: 
 * - User A purchases hero #1 at full price
 * - `lastPurchaseTime` is set to current `block.timestamp`
 * - Hero price doubles as normal
 * 
 * **Transaction 2+ (Exploitation)**:
 * - Attacker (who is a miner or has miner cooperation) waits for organic transactions
 * - When profitable, miner manipulates `block.timestamp` to be artificially far in the future
 * - This makes `timeSinceLastPurchase` artificially large, triggering maximum discount (50% off)
 * - Attacker purchases hero at heavily discounted price
 * - Attacker can then immediately resell or benefit from the price manipulation
 * 
 * **WHY MULTI-TRANSACTION DEPENDENCY IS REQUIRED:**
 * 
 * 1. **State Accumulation**: The vulnerability requires the `lastPurchaseTime` to be set in a previous transaction before it can be exploited in subsequent transactions.
 * 
 * 2. **Time-Based State Evolution**: The discount calculation depends on the time difference between two separate transactions, making single-transaction exploitation impossible.
 * 
 * 3. **Cross-Transaction Manipulation**: The attacker needs to observe existing state from previous purchases and then manipulate timestamps in future transactions to exploit the pricing mechanism.
 * 
 * 4. **Persistent State Dependency**: Each purchase updates the `lastPurchaseTime`, creating a chain of state changes that persist across transactions and enable the vulnerability.
 * 
 * **EXPLOITATION IMPACT:**
 * - Miners can manipulate timestamps to purchase heroes at significant discounts
 * - Creates unfair advantages for miners or those with mining pool cooperation
 * - Allows systematic exploitation of the time-based pricing mechanism
 * - Can be repeatedly exploited across multiple heroes and transactions
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
        uint256 lastPurchaseTime; // Added lastPurchaseTime to store purchase timestamp
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
	// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
function purchaseHero(uint _heroId) public payable {
		require(isPaused == false);
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====

		// Time-based pricing mechanism - price decreases over time since last purchase
		uint256 timeSinceLastPurchase = block.timestamp - heroes[_heroId].lastPurchaseTime;
		uint256 hoursElapsed = timeSinceLastPurchase / 3600; // Convert to hours
		
		// Calculate time-based discount (5% per hour, max 50% discount)
		uint256 discountPercent = hoursElapsed * 5;
		if (discountPercent > 50) {
			discountPercent = 50;
		}
		
		uint256 discountedPrice = heroes[_heroId].currentPrice * (100 - discountPercent) / 100;
		require(msg.value == discountedPrice);
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

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
		// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
		
		// Update the last purchase timestamp for future discount calculations
		heroes[_heroId].lastPurchaseTime = block.timestamp;
		// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
        heroes.push(Hero(heroName,ownerAddress,currentPrice,0));
    }
	
}
