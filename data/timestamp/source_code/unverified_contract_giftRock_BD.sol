/*
 * ===== SmartInject Injection Details =====
 * Function      : giftRock
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
 * Introduced a timestamp-dependent gift cooldown mechanism that creates a multi-transaction vulnerability. The function now tracks when each owner last gifted a rock using block.timestamp and enforces a 24-hour cooldown period. This creates several exploitation vectors:
 * 
 * 1. **Timestamp Manipulation**: Miners can manipulate block.timestamp to bypass cooldowns by setting timestamps that appear to be 24+ hours in the future
 * 2. **Clock Drift Exploitation**: Network participants can exploit natural timestamp variations between blocks
 * 3. **Multi-Transaction State Race**: Users can plan multiple rapid gift transactions around timestamp boundaries
 * 
 * **Multi-Transaction Exploitation Scenarios:**
 * 
 * **Scenario 1 - Miner Timestamp Manipulation:**
 * - Transaction 1: Owner gifts rock A (lastGiftTime[owner] = T1)
 * - Miner manipulates timestamp in next block to T1 + 1 days + 1 second
 * - Transaction 2: Same owner can immediately gift rock B, bypassing intended cooldown
 * 
 * **Scenario 2 - Timestamp Boundary Exploitation:**
 * - Transaction 1: Owner gifts rock A at timestamp T1
 * - Attacker monitors mempool and calculates exactly when T1 + 1 days will be reached
 * - Transaction 2: Owner submits gift transaction for rock B precisely at the boundary
 * - Due to block timestamp variations, the cooldown check may pass even if less than 24 hours have actually elapsed
 * 
 * **Scenario 3 - State Accumulation Attack:**
 * - Transaction 1: Owner gifts rock A (establishes lastGiftTime state)
 * - Attacker waits for timestamp manipulation opportunity
 * - Transaction 2: Owner gifts rock B using manipulated timestamp
 * - Transaction 3: Owner gifts rock C, continuing the exploit chain
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Persistence**: The vulnerability requires lastGiftTime state to be set in a first transaction
 * 2. **Temporal Dependency**: The exploit depends on the relationship between stored timestamp and current block.timestamp
 * 3. **Cooldown Logic**: The vulnerability only manifests when there's a previous gift to compare against
 * 4. **Cannot be Atomic**: Single transaction cannot exploit timestamp manipulation since the state change and check happen in same block
 * 
 * This creates a realistic, stateful vulnerability that requires multiple transactions and persistent state changes to exploit, while maintaining the original function's core gifting functionality.
 */
pragma solidity ^0.4.2;

// This is a revised version of the original EtherRock contract 0x37504ae0282f5f334ed29b4548646f887977b7cc with all the rock owners and rock properties the same at the time this new contract is being deployed.
// The original contract at 0x37504ae0282f5f334ed29b4548646f887977b7cc had a simple mistake in the buyRock() function. The line:
// require(rocks[rockNumber].currentlyForSale = true);
// Had to have double equals, as follows:
// require(rocks[rockNumber].currentlyForSale == true);
// Therefore in the original contract, anyone could buy anyone elses rock for the same price the owner purchased it for (regardless of whether the owner chose to sell it or not)

contract EtherRock {
    
    struct Rock {
        address owner;
        bool currentlyForSale;
        uint price;
        uint timesSold;
    }
    
    mapping (uint => Rock) public rocks;
    
    mapping (address => uint[]) public rockOwners;

    uint public latestNewRockForSale;
    
    address owner;
    
    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
    
    function EtherRock() {
        
        latestNewRockForSale = 11;
        
        rocks[0].owner = 0x789c778b340f17eb046a5a8633e362468aceeff6;
        rocks[0].currentlyForSale = true;
        rocks[0].price = 10000000000000000000;
        rocks[0].timesSold = 2;
        rockOwners[0x789c778b340f17eb046a5a8633e362468aceeff6].push(0);
        
        rocks[1].owner = 0x9a643a42748243f80243a65666146a2e1bd5c6aa;
        rocks[1].currentlyForSale = false;
        rocks[1].price = 2000000000000000;
        rocks[1].timesSold = 3;
        rockOwners[0x9a643a42748243f80243a65666146a2e1bd5c6aa].push(1);
        
        rocks[2].owner = 0x5d5d6543d73066e69424ce2756cc34cbfe4c368c;
        rocks[2].currentlyForSale = false;
        rocks[2].price = 5000000000000000;
        rocks[2].timesSold = 1;
        rockOwners[0x5d5d6543d73066e69424ce2756cc34cbfe4c368c].push(2);
        
        rocks[3].owner = 0xe34501580dc9591211afc7c13f16ddf591c87cde;
        rocks[3].currentlyForSale = true;
        rocks[3].price = 1000000000000000000;
        rocks[3].timesSold = 1;
        rockOwners[0xe34501580dc9591211afc7c13f16ddf591c87cde].push(3);
        
        rocks[4].owner = 0x93cdb0a93fc36f6a53ed21ecf6305ab80d06beca;
        rocks[4].currentlyForSale = true;
        rocks[4].price = 1000000000000000000;
        rocks[4].timesSold = 1;
        rockOwners[0x93cdb0a93fc36f6a53ed21ecf6305ab80d06beca].push(4);
        
        rocks[5].owner = 0x9467d05ee1c90010a657e244f626194168596583;
        rocks[5].currentlyForSale = true;
        rocks[5].price = 42000000000000000000;
        rocks[5].timesSold = 1;
        rockOwners[0x9467d05ee1c90010a657e244f626194168596583].push(5);
        
        rocks[6].owner = 0xb6e2e5e06397dc522db58faa064f74c95322b58e;
        rocks[6].currentlyForSale = true;
        rocks[6].price = 60000000000000000;
        rocks[6].timesSold = 1;
        rockOwners[0xb6e2e5e06397dc522db58faa064f74c95322b58e].push(6);
        
        rocks[7].owner = 0xbcddcf35880443b6a1f32f07009097e95c327716;
        rocks[7].currentlyForSale = true;
        rocks[7].price = 100000000000000000;
        rocks[7].timesSold = 1;
        rockOwners[0xbcddcf35880443b6a1f32f07009097e95c327716].push(7);
        
        rocks[8].owner = 0xf7007f39a41d87c669bd9beadc3d5cc2ef5a32be;
        rocks[8].currentlyForSale = false;
        rocks[8].price = 65000000000000000;
        rocks[8].timesSold = 1;
        rockOwners[0xf7007f39a41d87c669bd9beadc3d5cc2ef5a32be].push(8);
        
        rocks[9].owner = 0xf7007f39a41d87c669bd9beadc3d5cc2ef5a32be;
        rocks[9].currentlyForSale = true;
        rocks[9].price = 10000000000000000000;
        rocks[9].timesSold = 1;
        rockOwners[0xf7007f39a41d87c669bd9beadc3d5cc2ef5a32be].push(9);
        
        rocks[10].owner = 0xd17e2bfe196470a9fefb567e8f5992214eb42f24;
        rocks[10].currentlyForSale = true;
        rocks[10].price = 200000000000000000;
        rocks[10].timesSold = 1;
        rockOwners[0xd17e2bfe196470a9fefb567e8f5992214eb42f24].push(10);
        
        rocks[11].currentlyForSale = true;
        rocks[11].price = 122000000000000000;
        
        owner = msg.sender;
    }
    
    function getRockInfo (uint rockNumber) returns (address, bool, uint, uint) {
        return (rocks[rockNumber].owner, rocks[rockNumber].currentlyForSale, rocks[rockNumber].price, rocks[rockNumber].timesSold);
    }
    
    function rockOwningHistory (address _address) returns (uint[]) {
        return rockOwners[_address];
    }
    
    function buyRock (uint rockNumber) payable {
        require(rocks[rockNumber].currentlyForSale == true);
        require(msg.value == rocks[rockNumber].price);
        rocks[rockNumber].currentlyForSale = false;
        rocks[rockNumber].timesSold++;
        if (rockNumber != latestNewRockForSale) {
            rocks[rockNumber].owner.transfer(rocks[rockNumber].price);
        }
        rocks[rockNumber].owner = msg.sender;
        rockOwners[msg.sender].push(rockNumber);
        if (rockNumber == latestNewRockForSale) {
            if (rockNumber != 99) {
                latestNewRockForSale++;
                rocks[latestNewRockForSale].price = 10**15 + (latestNewRockForSale**2 * 10**15);
                rocks[latestNewRockForSale].currentlyForSale = true;
            }
        }
    }
    
    function sellRock (uint rockNumber, uint price) {
        require(msg.sender == rocks[rockNumber].owner);
        require(price > 0);
        rocks[rockNumber].price = price;
        rocks[rockNumber].currentlyForSale = true;
    }
    
    function dontSellRock (uint rockNumber) {
        require(msg.sender == rocks[rockNumber].owner);
        rocks[rockNumber].currentlyForSale = false;
    }
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping (address => uint) public lastGiftTime;
    
    function giftRock (uint rockNumber, address receiver) {
        require(msg.sender == rocks[rockNumber].owner);
        
        // Anti-spam protection: 24-hour cooldown between gifts from same owner
        if (lastGiftTime[msg.sender] > 0) {
            require(block.timestamp >= lastGiftTime[msg.sender] + 1 days, "Gift cooldown not met");
        }
        
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        rocks[rockNumber].owner = receiver;
        rockOwners[receiver].push(rockNumber);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Update last gift timestamp for sender
        lastGiftTime[msg.sender] = block.timestamp;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }
    
    function() payable {
        
    }
    
    function withdraw() onlyOwner {
        owner.transfer(this.balance);
    }
    
}