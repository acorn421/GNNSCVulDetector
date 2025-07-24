/*
 * ===== SmartInject Injection Details =====
 * Function      : buyRock
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Reordered State Updates**: Moved the ownership transfer (`rocks[rockNumber].owner = msg.sender`) to occur AFTER the external call, creating a window for reentrancy exploitation.
 * 
 * 2. **State Persistence Exploitation**: The vulnerability exploits the fact that `rocks[rockNumber].currentlyForSale` is set to false early, but ownership isn't updated until after the external call. This creates a persistent state inconsistency that can be exploited across multiple transactions.
 * 
 * 3. **Multi-Transaction Attack Vector**: 
 *    - **Transaction 1**: Attacker calls `buyRock()` on a rock they want to exploit
 *    - **During Transfer Callback**: The attacker's contract receives the transfer callback and can call other functions like `sellRock()` to manipulate the state of rocks they don't actually own yet
 *    - **Transaction 2**: Attacker exploits the state inconsistencies created in Transaction 1 to buy rocks at incorrect prices or bypass ownership checks
 * 
 * 4. **Cross-Function State Manipulation**: During the reentrancy callback, the attacker can call `sellRock()` or `dontSellRock()` on rocks where the sale state is modified but ownership hasn't been transferred yet, creating exploitable state inconsistencies.
 * 
 * 5. **Accumulated State Exploitation**: The vulnerability requires multiple transactions because the attacker needs to:
 *    - First trigger the reentrancy to create state inconsistencies
 *    - Then exploit those inconsistencies in subsequent transactions
 *    - The state changes persist between transactions, enabling complex multi-step attacks
 * 
 * This creates a realistic reentrancy vulnerability that requires coordination across multiple transactions to fully exploit, making it a true stateful, multi-transaction vulnerability.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Store purchase state for cross-transaction exploitation
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        rocks[rockNumber].currentlyForSale = false;
        rocks[rockNumber].timesSold++;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Critical vulnerability: External call before ownership update
        // This allows reentrancy to manipulate state during callback
        if (rockNumber != latestNewRockForSale) {
            address previousOwner = rocks[rockNumber].owner;
            uint paymentAmount = rocks[rockNumber].price;
            
            // External call that enables reentrancy exploitation
            // During this callback, attacker can call other functions
            // to modify rock state before ownership is transferred
            previousOwner.transfer(paymentAmount);
            
            // State changes after external call - vulnerable to manipulation
            // If reentrancy occurs above, these state changes can be exploited
            rocks[rockNumber].owner = msg.sender;
            rockOwners[msg.sender].push(rockNumber);
        } else {
            // Direct ownership transfer for new rocks
            rocks[rockNumber].owner = msg.sender;
            rockOwners[msg.sender].push(rockNumber);
        }
        
        // New rock creation logic - can be exploited through accumulated state
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
        rocks[rockNumber].owner = receiver;
        rockOwners[receiver].push(rockNumber);
    }
    
    function() payable {
        
    }
    
    function withdraw() onlyOwner {
        owner.transfer(this.balance);
    }
    
}