/*
 * ===== SmartInject Injection Details =====
 * Function      : giftRock
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by adding an external call to the receiver before updating the ownership state. The vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Changes Made:**
 * 1. Added an external call `receiver.call.value(0)(bytes4(keccak256("onRockReceived(uint256)")), rockNumber)` to notify the receiver
 * 2. Placed this call BEFORE the state updates (violating Checks-Effects-Interactions pattern)
 * 3. State changes (`rocks[rockNumber].owner` and `rockOwners[receiver]`) happen after the external call
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls giftRock(1, maliciousContract) where maliciousContract is controlled by attacker
 * 2. **During external call**: maliciousContract's fallback/onRockReceived function re-enters giftRock(1, anotherAddress)
 * 3. **State confusion**: Since owner hasn't been updated yet, the require check passes again
 * 4. **Transaction 2**: Attacker can exploit the inconsistent state - rock ownership may be duplicated or confused
 * 5. **Subsequent transactions**: Attacker leverages the persistent state inconsistencies to claim rocks improperly
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability creates persistent state inconsistencies that accumulate across transactions
 * - Each reentrancy call during Transaction 1 leaves the contract in an inconsistent state
 * - The attacker needs separate transactions to fully exploit these persistent state changes
 * - The rockOwners array may contain duplicate entries that can be exploited in later transactions
 * - Other functions like sellRock or dontSellRock may be called in subsequent transactions using the confused ownership state
 * 
 * **Realistic Nature:**
 * - Adding a notification callback to gift recipients is a common feature in NFT-like contracts
 * - The vulnerability appears as a genuine attempt to implement receiver notification
 * - The code maintains the original function's behavior while introducing the security flaw
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
    
    function giftRock (uint rockNumber, address receiver) {
        require(msg.sender == rocks[rockNumber].owner);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add external call to notify receiver before state changes
        if (receiver.call.value(0)(bytes4(keccak256("onRockReceived(uint256)")), rockNumber)) {
            // Callback succeeded, continue with gift
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        rocks[rockNumber].owner = receiver;
        rockOwners[receiver].push(rockNumber);
    }
    
    function() payable {
        
    }
    
    function withdraw() onlyOwner {
        owner.transfer(this.balance);
    }
    
}