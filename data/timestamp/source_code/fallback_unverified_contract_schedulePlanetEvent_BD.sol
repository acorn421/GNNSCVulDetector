/*
 * ===== SmartInject Injection Details =====
 * Function      : schedulePlanetEvent
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue where the contract relies on 'now' (block.timestamp) for time-critical operations. The vulnerability is stateful and multi-transaction because: 1) First transaction calls schedulePlanetEvent() to set up the event schedule, 2) State persists between transactions (planetEventSchedule, planetEventReward, planetEventActive mappings), 3) Second transaction calls claimEventReward() after the scheduled time. Miners can manipulate block timestamps within reasonable bounds (typically 15 seconds) to potentially claim rewards slightly early or delay them. This creates a timing attack vector where malicious miners could influence when events can be claimed.
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
    
    mapping (uint => uint256) public planetEventSchedule;
    mapping (uint => uint256) public planetEventReward;
    mapping (uint => bool) public planetEventActive;
    
    modifier onlyCeo() {
        require(msg.sender == ceoAddress);
        _;
    }

    // Schedule a resource bonus event for a planet
    function schedulePlanetEvent(uint _planetId, uint256 _eventDuration) public {
        require(planets[_planetId].ownerAddress == msg.sender);
        require(_eventDuration > 0 && _eventDuration <= 86400); // Max 24 hours
        
        // Schedule event to end at current timestamp + duration
        planetEventSchedule[_planetId] = now + _eventDuration;
        planetEventReward[_planetId] = planets[_planetId].curPrice / 10; // 10% of planet price as reward
        planetEventActive[_planetId] = true;
    }
    
    // Claim the scheduled event reward
    function claimEventReward(uint _planetId) public {
        require(planets[_planetId].ownerAddress == msg.sender);
        require(planetEventActive[_planetId] == true);
        
        // Vulnerable: Uses block.timestamp for time comparison
        // Miners can manipulate timestamp within reasonable bounds
        if (now >= planetEventSchedule[_planetId]) {
            uint256 reward = planetEventReward[_planetId];
            
            // Add reward to planet resources
            planets[_planetId].curResources += reward;
            
            // Reset event
            planetEventActive[_planetId] = false;
            planetEventSchedule[_planetId] = 0;
            planetEventReward[_planetId] = 0;
        }
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