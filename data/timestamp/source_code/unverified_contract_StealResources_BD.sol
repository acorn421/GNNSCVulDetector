/*
 * ===== SmartInject Injection Details =====
 * Function      : StealResources
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
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability through a time-based attack cooldown system combined with accumulated time bonuses. The vulnerability requires:
 * 
 * 1. **State Variables Added (assumed to exist)**:
 *    - `mapping(address => uint256) lastAttackTime` - Tracks last attack timestamp per user
 *    - `uint256 attackCooldown` - Minimum time between attacks (assumed to be set to reasonable value like 300 seconds)
 * 
 * 2. **Multi-Transaction Exploitation Pattern**:
 *    - **Transaction 1**: Attacker performs initial attack, establishing their `lastAttackTime`
 *    - **Wait Period**: Attacker waits for optimal timing conditions
 *    - **Transaction 2+**: Attacker exploits timestamp manipulation to maximize time bonus and bypass cooldowns
 * 
 * 3. **Vulnerability Mechanics**:
 *    - **Cooldown Bypass**: Miners can manipulate `block.timestamp` to make cooldown periods appear elapsed
 *    - **Time Bonus Exploitation**: Attackers can manipulate timestamps to artificially inflate `timeSinceLastAttack`, gaining unfair bonuses up to 25%
 *    - **Accumulated State Dependency**: Each attack updates `lastAttackTime`, creating state that persists and affects future transactions
 * 
 * 4. **Why Multi-Transaction is Required**:
 *    - Initial attack establishes baseline timestamp in state
 *    - Subsequent attacks compare against stored timestamps
 *    - Time bonuses only meaningful with historical state data
 *    - Cooldown mechanism inherently requires multiple transactions over time
 * 
 * 5. **Realistic Attack Scenarios**:
 *    - Miners could set favorable timestamps to extend time bonuses
 *    - Coordinated attacks could exploit timestamp manipulation across multiple blocks
 *    - Attackers could time transactions to maximize bonuses while bypassing cooldowns
 * 
 * The vulnerability maintains all original functionality while adding timestamp-dependent logic that creates genuine multi-transaction exploitation opportunities.
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
    

    uint256 attackCost = 10000000000000000;
    uint256 defenseCost = 10000000000000000;
    
    uint randNonce = 0;
    bool planetsAreInitiated;

    // ===== Added declarations for timestamp-based attack cooldown system =====
    mapping(address => uint256) public lastAttackTime;
    uint256 public attackCooldown = 3600; // 1 hour in seconds

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

    function StealResources(uint _planetId) public {
        // Verify that the address actually own a planet
        require(addressPlanetsCount[msg.sender] > 0);

        // We verify that this address doesn't own this planet
        require(planets[_planetId].ownerAddress != msg.sender);

        // We verify that this planet has resources
        require(planets[_planetId].curResources > 0);

        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Time-based attack cooldown system - prevent spam attacks
        require(now >= lastAttackTime[msg.sender] + attackCooldown);
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        // Transfer a random amount of resources (between 1% and 90%) of the resources of the planet to the stealer if it's attack is better than the planet's owner defense
        if(addressAttackCount[msg.sender] > addressDefenseCount[planets[_planetId].ownerAddress]) {
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            // Calculate time-based attack bonus (accumulated over multiple blocks)
            uint256 timeSinceLastAttack = now - lastAttackTime[msg.sender];
            uint256 timeBonus = 0;
            
            // Bonus increases over time, but caps at 25% after 1 hour
            if(timeSinceLastAttack > 3600) {
                timeBonus = 25; // Maximum bonus after 1 hour
            } else {
                timeBonus = (timeSinceLastAttack * 25) / 3600; // Linear scaling
            }
            
            // Store current attack timestamp for future calculations
            lastAttackTime[msg.sender] = now;
            
            // Generate a random number between 1 and 49, enhanced by time bonus
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            uint random = uint(keccak256(now, msg.sender, randNonce)) % 49;
            randNonce++;
            
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            // Calculate and transfer the random amount of resources with time bonus
            uint256 baseStealPercent = 50 + random + timeBonus;
            if(baseStealPercent > 99) baseStealPercent = 99; // Cap at 99%
            
            uint256 resourcesStealable = (planets[_planetId].curResources * baseStealPercent) / 100;
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            msg.sender.transfer(resourcesStealable);
            
            // Save the new resources count
            planets[_planetId].curResources = planets[_planetId].curResources - resourcesStealable;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        } else {
            // Even failed attacks update the timestamp to prevent timing manipulation
            lastAttackTime[msg.sender] = now;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
