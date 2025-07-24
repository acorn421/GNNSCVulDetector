/*
 * ===== SmartInject Injection Details =====
 * Function      : purchasePlanet
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by moving all critical state updates (ownership counts, planet owner, price) to occur AFTER the external call to the previous owner. This creates a window where the contract state is inconsistent and can be exploited through multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. **Stored previous owner address** before external call to avoid reading potentially modified state
 * 2. **Moved all state updates** (addressPlanetsCount, planets[_planetId].ownerAddress, planets[_planetId].curPrice) to occur AFTER the external call
 * 3. **Preserved function signature and logic** while introducing the vulnerability through reordering
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker deploys malicious contract and purchases a planet, making the malicious contract the owner
 * 2. **Transaction 2**: Victim attempts to purchase the planet from the malicious contract
 * 3. **During Transaction 2**: When the transfer to the malicious contract executes, the malicious contract's fallback function calls back into purchasePlanet
 * 4. **Reentrancy Effect**: The reentrant call finds the planet still owned by the malicious contract (state not yet updated), allowing multiple purchases with inconsistent state
 * 5. **Transaction 3+**: The attacker can exploit the accumulated state inconsistencies to own multiple planets while only paying once, or manipulate ownership counts
 * 
 * **Why Multi-Transaction is Required:**
 * - The malicious contract must first become a planet owner (separate transaction)
 * - The vulnerability only triggers when a legitimate user tries to purchase from the malicious owner
 * - The exploit builds up state inconsistencies over multiple reentrant calls
 * - Each subsequent transaction can exploit the accumulated inconsistent state between ownership records and actual ownership
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Store previous owner before external call
        address previousOwner = planets[_planetId].ownerAddress;
        
        // VULNERABILITY: External call to previous owner before state updates
        // This allows the previous owner to re-enter and manipulate state
        previousOwner.transfer(commissionOwner);

        // Keep 5% in the resources of the planet (before ownership change)
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        planets[_planetId].curResources =  planets[_planetId].curResources + commission5percent;

        // Transfer the 5% commission to the developer
        ceoAddress.transfer(commission5percent);                  
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

        // VULNERABILITY: Critical state updates happen AFTER external calls
        // This creates a window where planet ownership and counts are inconsistent
        
        // Reduce number of planets for previous owner
        addressPlanetsCount[previousOwner] = addressPlanetsCount[previousOwner] - 1;
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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