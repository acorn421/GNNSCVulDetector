/*
 * ===== SmartInject Injection Details =====
 * Function      : purchaseHero
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Added State Variable**: Introduced `mapping(address => uint256) public pendingRefunds` to track pending refunds for previous hero owners.
 * 
 * 2. **Introduced Refund Mechanism**: Modified the function to add commission amounts to `pendingRefunds` mapping before processing them.
 * 
 * 3. **Added External Call Before State Updates**: Implemented a refund processing mechanism that makes an external call to the previous owner BEFORE updating the hero ownership and price.
 * 
 * 4. **Used Vulnerable call() Pattern**: Replaced secure `transfer()` with vulnerable `call.value()` which allows reentrancy and doesn't limit gas.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract that can receive Ether
 * - Attacker purchases a hero, becoming the owner
 * - The `pendingRefunds` mapping now has the attacker's address
 * 
 * **Transaction 2 (Exploit):**
 * - Another user attempts to purchase the same hero from the attacker
 * - The function adds commission to `pendingRefunds[attacker]`
 * - When processing the refund, it calls `attacker.call.value(refundAmount)()`
 * - The attacker's contract receives the call and immediately calls `purchaseHero` again
 * - During reentrancy, the attacker can manipulate the purchase process before the original state updates complete
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Accumulation**: The vulnerability requires the attacker to first become a hero owner (Transaction 1), establishing state that will be exploited later.
 * 
 * 2. **Refund State Dependency**: The `pendingRefunds` mapping must be populated with the attacker's address before the reentrancy can occur.
 * 
 * 3. **Ownership Sequence**: The exploit depends on the sequence where the attacker first owns a hero, then someone else tries to buy it, triggering the refund mechanism.
 * 
 * 4. **Persistent State Exploitation**: The vulnerability exploits the persistent state of hero ownership and pending refunds that accumulate across multiple transactions.
 * 
 * **Exploitation Impact:**
 * - Attacker can receive refunds multiple times before state updates
 * - Hero ownership and pricing can be manipulated during reentrancy
 * - The vulnerability allows drainage of contract funds through repeated refund claims
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
	// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
// New state variable for pending refunds (to be added to contract)
mapping(address => uint256) public pendingRefunds;

function purchaseHero(uint _heroId) public payable {
	require(msg.value == heroes[_heroId].currentPrice);
	require(isPaused == false);

	// Calculate the 10% value
	uint256 devFee = (msg.value / 10);

	// Calculate the hero owner commission on this sale		
	uint256 commissionOwner = msg.value - devFee; // => 90%
	
	// Store previous owner for refund processing
	address previousOwner = heroes[_heroId].ownerAddress;
	
	// Add commission to pending refunds for previous owner
	pendingRefunds[previousOwner] += commissionOwner;
	
	// Process pending refund with external call BEFORE state updates
	if (pendingRefunds[previousOwner] > 0) {
		uint256 refundAmount = pendingRefunds[previousOwner];
		pendingRefunds[previousOwner] = 0;
		
		// External call to previous owner - vulnerable to reentrancy
		previousOwner.call.value(refundAmount)();
	}

	// Transfer the 10% commission to the developer
	devFeeAddress.transfer(devFee); // => 10% 						

	// Update the hero owner and set the new price (after external calls)
	heroes[_heroId].ownerAddress = msg.sender;
	heroes[_heroId].currentPrice = mul(heroes[_heroId].currentPrice, 2);
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
	
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
        heroes.push(Hero(heroName,ownerAddress,currentPrice));
    }
	
}