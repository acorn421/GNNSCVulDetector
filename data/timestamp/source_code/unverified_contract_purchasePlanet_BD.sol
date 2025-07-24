/*
 * ===== SmartInject Injection Details =====
 * Function      : purchasePlanet
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
 * Injected a stateful, multi-transaction Timestamp Dependence vulnerability that requires multiple planet purchases to exploit effectively. The vulnerability introduces time-based pricing logic using block.timestamp that can be manipulated by miners through multiple transactions:
 * 
 * 1. **State Persistence**: Added `lastPurchaseTime` and `purchaseCount` to planet state (requires Planet struct modification)
 * 2. **Time-based Logic**: Implemented surge pricing based on time intervals between purchases
 * 3. **Timestamp Manipulation**: Used block.timestamp for "random" bonus resource calculation
 * 4. **Multi-Transaction Exploitation**: Requires sequence of purchases to build up exploitable state
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: Attacker (miner) purchases planet, setting lastPurchaseTime
 * 2. **Transaction 2**: Attacker manipulates block.timestamp to be within 1 hour of previous purchase, triggering surge pricing logic
 * 3. **Transaction 3+**: Attacker can repeatedly exploit timestamp manipulation for bonus resources and price manipulation
 * 
 * **Why Multi-Transaction Required:**
 * - State accumulation through purchaseCount and lastPurchaseTime
 * - Time-based conditions require previous purchase timestamps to be stored
 * - Surge pricing logic depends on historical purchase timing
 * - Miners need multiple blocks to effectively manipulate timestamps
 * 
 * **Realistic Attack Scenarios:**
 * - Miners can manipulate timestamps to avoid surge pricing
 * - Predictable "random" bonus resources based on timestamp patterns
 * - Price manipulation through timing control
 * - State accumulation makes successive exploits more profitable
 */
pragma solidity ^0.4.18;

/*
Game Name: CryptoPlanets
Game Link: https://cryptoplanets.com/
Rules: 
- Acquire planets
- Steal resources (ETH) from other planets
*/

contract CryptoPlanets {

    address ceoAddress = 0x8e6DBF31540d2299a674b8240596ae85ebD21314;
    
    modifier onlyCeo() {
        require (msg.sender == ceoAddress);
        _;
    }
    
    struct Planet {
        string name;
        address ownerAddress;
        uint256 curPrice;
        uint256 curResources;
        uint256 lastPurchaseTime;     // <-- Added member
        uint256 purchaseCount;        // <-- Added member for frequency
    }
    Planet[] planets;


    // How many shares an addres own
    mapping (address => uint) public addressPlanetsCount;
    mapping (address => uint) public addressAttackCount;
    mapping (address => uint) public addressDefenseCount;
    

    uint256 attackCost = 10000000000000000;
    uint256 defenseCost = 10000000000000000;
    
    uint randNonce = 0;
    bool planetsAreInitiated;

    /*
    This function allows players to purchase planets from other players. 
    The price of the planets is automatically multiplied by 1.5 after each purchase.
    */
    function purchasePlanet(uint _planetId) public payable {
        require(msg.value == planets[_planetId].curPrice);

        // Calculate the 5% value
        uint256 commission5percent = ((msg.value / 10)/2);

        // Calculate the owner commission on this sale & transfer the commission to the owner.      
        uint256 commissionOwner = msg.value - (commission5percent * 2); // => 95%
        planets[_planetId].ownerAddress.transfer(commissionOwner);

        // Reduce number of planets for previous owner
        addressPlanetsCount[planets[_planetId].ownerAddress] = addressPlanetsCount[planets[_planetId].ownerAddress] - 1;

        // Keep 5% in the resources of the planet
        planets[_planetId].curResources =  planets[_planetId].curResources + commission5percent;

        // Transfer the 5% commission to the developer
        ceoAddress.transfer(commission5percent);                  

        // Update the planet owner and set the new price
        planets[_planetId].ownerAddress = msg.sender;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // VULNERABILITY: Time-based pricing with state accumulation
        // Store purchase timestamp for future price calculations
        planets[_planetId].lastPurchaseTime = block.timestamp;
        
        // Apply time-based price multiplier based on accumulated purchase frequency
        uint256 timeSinceLastPurchase = block.timestamp - planets[_planetId].lastPurchaseTime;
        
        // If planet was purchased recently (within 1 hour), apply surge pricing
        if (timeSinceLastPurchase < 3600) {
            // Price surge: 2x multiplier for rapid purchases
            planets[_planetId].curPrice = planets[_planetId].curPrice * 2;
        } else {
            // Standard price increase: 1.5x multiplier
            planets[_planetId].curPrice = planets[_planetId].curPrice + (planets[_planetId].curPrice / 2);
        }
        
        // Track purchase frequency for this planet (state accumulation)
        planets[_planetId].purchaseCount += 1;
        
        // Additional vulnerability: Use block.timestamp for "random" bonus resources
        // This creates predictable patterns that miners can exploit
        if (block.timestamp % 100 < 20) {
            // 20% chance based on timestamp - miners can manipulate this
            planets[_planetId].curResources += commission5percent;
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

        // Increment number of planets for new owner
        addressPlanetsCount[msg.sender] = addressPlanetsCount[msg.sender] + 1;
    }

    //User is purchasing attack
    function purchaseAttack() payable {

        // Verify that user is paying the correct price
        require(msg.value == attackCost);
        
        // We transfer the amount paid to the owner
        ceoAddress.transfer(msg.value);

        addressAttackCount[msg.sender]++;
    }

    //User is purchasing defense
    function purchaseDefense() payable {
        // Verify that user is paying the correct price
        require(msg.value == defenseCost);
        
        // We transfer the amount paid to the owner
        ceoAddress.transfer(msg.value);
        
        addressDefenseCount[msg.sender]++;
    }

    function StealResources(uint _planetId) {
        // Verify that the address actually own a planet
        require(addressPlanetsCount[msg.sender] > 0);

        // We verify that this address doesn't own this planet
        require(planets[_planetId].ownerAddress != msg.sender);

        // We verify that this planet has resources
        require(planets[_planetId].curResources > 0);

        // Transfer a random amount of resources (between 1% and 90%) of the resources of the planet to the stealer if it's attack is better than the planet's owner defense
        if(addressAttackCount[msg.sender] > addressDefenseCount[planets[_planetId].ownerAddress]) {
            // Generate a random number between 1 and 49
            uint random = uint(keccak256(now, msg.sender, randNonce)) % 49;
            randNonce++;
            
            // Calculate and transfer the random amount of resources to the stealer
            uint256 resourcesStealable = (planets[_planetId].curResources * (50 + random)) / 100;
            msg.sender.transfer(resourcesStealable);
            
            // Save the new resources count
            planets[_planetId].curResources = planets[_planetId].curResources - resourcesStealable;
        }

    }
    
    // This function will return the details for the connected user (planets count, attack count, defense count)
    function getUserDetails(address _user) public view returns(uint, uint, uint) {
        return(addressPlanetsCount[_user], addressAttackCount[_user], addressDefenseCount[_user]);
    }
    
    // This function will return the details of a planet
    function getPlanet(uint _planetId) public view returns (
        string name,
        address ownerAddress,
        uint256 curPrice,
        uint256 curResources,
        uint ownerAttack,
        uint ownerDefense
    ) {
        Planet storage _planet = planets[_planetId];

        name = _planet.name;
        ownerAddress = _planet.ownerAddress;
        curPrice = _planet.curPrice;
        curResources = _planet.curResources;
        ownerAttack = addressAttackCount[_planet.ownerAddress];
        ownerDefense = addressDefenseCount[_planet.ownerAddress];
    }
    
    
    // The dev can use this function to create new planets.
    function createPlanet(string _planetName, uint256 _planetPrice) public onlyCeo {
        uint planetId = planets.push(Planet(_planetName, ceoAddress, _planetPrice, 0, 0, 0)) - 1;
    }
    
    // Initiate functions that will create the planets
    function InitiatePlanets() public onlyCeo {
        require(planetsAreInitiated == false);
        createPlanet("Blue Lagoon", 100000000000000000); 
        createPlanet("GreenPeace", 100000000000000000); 
        createPlanet("Medusa", 100000000000000000); 
        createPlanet("O'Ranger", 100000000000000000); 
        createPlanet("Queen", 90000000000000000); 
        createPlanet("Citrus", 90000000000000000); 
        createPlanet("O'Ranger II", 90000000000000000); 
        createPlanet("Craterion", 50000000000000000);
        createPlanet("Dark'Air", 50000000000000000);

    }
}
