/*
 * ===== SmartInject Injection Details =====
 * Function      : purchaseAttack
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through a time-based attack bonus system. The vulnerability requires these additional state variables:
 * - mapping(address => uint256) lastAttackPurchaseBlock; // Tracks last purchase timestamp per user
 * - mapping(address => uint256) consecutiveAttackPurchases; // Tracks consecutive purchases in same time window
 * 
 * **Exploitation Mechanism:**
 * 1. **First Transaction**: User purchases attack normally, gets 1 attack point, stores current timestamp
 * 2. **Subsequent Transactions**: If user purchases again within same hour (based on block.timestamp), they get exponential bonus attacks (3, 7, 15, etc.)
 * 3. **Miner Manipulation**: Miners can manipulate block.timestamp to:
 *    - Keep multiple transactions within same hour window to get massive attack bonuses
 *    - Artificially extend time windows to accumulate more bonus attacks
 *    - Reset their consecutive purchase counter by manipulating timestamp to appear in different hours
 * 
 * **Multi-Transaction Requirements:**
 * - Single transaction gives minimal benefit (1 attack)
 * - Multiple transactions within manipulated timeframe provide exponential attack advantages
 * - State persists between transactions, enabling accumulated exploitation
 * - The vulnerability requires sequence of purchases across multiple blocks with timestamp manipulation
 * 
 * **Real-World Impact:**
 * - Attackers can accumulate hundreds of attack points for same cost
 * - Breaks game balance in StealResources function
 * - Miners have unfair advantage in the game economy
 * - Creates timing-based economic exploitation vector
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
    }
    Planet[] planets;


    // How many shares an addres own
    mapping (address => uint) public addressPlanetsCount;
    mapping (address => uint) public addressAttackCount;
    mapping (address => uint) public addressDefenseCount;
    
    // === ADDED FOR FIX (start) ===
    mapping(address => uint256) public lastAttackPurchaseBlock;
    mapping(address => uint256) public consecutiveAttackPurchases;
    // === ADDED FOR FIX (end) ===
    
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
        planets[_planetId].curPrice = planets[_planetId].curPrice + (planets[_planetId].curPrice / 2);

        // Increment number of planets for new owner
        addressPlanetsCount[msg.sender] = addressPlanetsCount[msg.sender] + 1;
    }

    //User is purchasing attack
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
function purchaseAttack() payable {
        // Verify that user is paying the correct price
        require(msg.value == attackCost);
        
        // We transfer the amount paid to the owner
        ceoAddress.transfer(msg.value);

        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Time-based attack bonus system - more attacks purchased in same block get exponential bonus
        uint256 currentBlock = block.timestamp / 3600; // Hour-based grouping
        if (lastAttackPurchaseBlock[msg.sender] == currentBlock) {
            // Consecutive purchases in same hour get bonus attacks
            uint256 bonus = (consecutiveAttackPurchases[msg.sender] * 2) + 1;
            addressAttackCount[msg.sender] += bonus;
            consecutiveAttackPurchases[msg.sender]++;
        } else {
            // First purchase in this hour
            addressAttackCount[msg.sender]++;
            consecutiveAttackPurchases[msg.sender] = 1;
        }
        
        lastAttackPurchaseBlock[msg.sender] = currentBlock;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
        uint planetId = planets.push(Planet(_planetName, ceoAddress, _planetPrice, 0)) - 1;
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
