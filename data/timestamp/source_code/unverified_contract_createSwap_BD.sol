/*
 * ===== SmartInject Injection Details =====
 * Function      : createSwap
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability with the following components:
 * 
 * **Changes Made:**
 * 1. **Time-based Dynamic Pricing**: Added pricing logic that depends on the current hour derived from block.timestamp (now / 3600) % 24, creating different price multipliers for different time periods
 * 2. **Variable Expiration Windows**: Modified expiration logic to depend on timestamp modulo operations (now % 300), creating different expiration periods based on 5-minute windows
 * 3. **Persistent State Impact**: The timestamp-dependent calculations affect the stored Swap struct's amountGet and expires fields, which persist in contract state
 * 
 * **Multi-Transaction Exploitation:**
 * This vulnerability requires multiple transactions to exploit effectively:
 * 
 * 1. **Transaction 1 (Setup)**: Attacker monitors the blockchain and waits for favorable timestamp conditions (e.g., approaching a 5-minute window boundary or optimal hour)
 * 2. **Transaction 2 (Exploit)**: Attacker creates a swap when block.timestamp conditions are most favorable (e.g., during discount hours AND in the first half of a 5-minute window for longer expiration)
 * 3. **Transaction 3 (Benefit)**: The created swap persists with the favorable terms, and the attacker can later execute or cancel it based on the advantageous pricing and expiration they secured
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability cannot be exploited in a single transaction because the benefit comes from the persistent state changes (stored Swap with favorable terms)
 * - Miners or sophisticated attackers need to time their createSwap calls across multiple blocks to maximize the timestamp-dependent benefits
 * - The stateful nature means the timestamp-dependent values are locked into the Swap struct and persist between transactions
 * - Exploitation requires monitoring timestamp patterns over time and executing transactions at optimal moments
 * 
 * **Exploitation Scenarios:**
 * - Miners can manipulate block timestamps within the ~15-second tolerance to hit favorable pricing windows
 * - Attackers can create swaps with longer expiration times and better pricing by timing their transactions
 * - Front-running attacks where attackers observe pending transactions and time their own to get better terms
 * - The vulnerability accumulates value over multiple swaps created at different timestamp-advantageous moments
 */
pragma solidity ^0.4.16;

contract ERC20 {
    
    string public name;
    function totalSupply() constant returns (uint);
    function balanceOf(address _owner) constant returns (uint);
    function allowance(address _owner, address _spender) constant returns (uint);
    function transfer(address _to, uint _value) returns (bool);
    function transferFrom(address _from, address _to, uint _value) returns (bool);
    function approve(address _spender, uint _value) returns (bool);

}

contract Ownable {

    address public owner;

    function Ownable() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0));
        owner = newOwner;
    }
}

contract Pausable is Ownable {

    bool public paused = false;

    modifier whenNotPaused() {
        require(!paused);
        _;
    }

    modifier whenPaused() {
        require(paused);
        _;
    }

    function pause() public onlyOwner whenNotPaused {
        paused = true;
    }

    function unpause() public onlyOwner whenPaused {
        paused = false;
    }
}

contract OTC is Pausable {

    struct Swap {
        uint256 expires;
        uint256 amountGive;
        uint256 amountGet;
        address tokenGet;
        address tokenGive;
        address buyer;
        address seller;
    }

    Swap[] public swaps;

    event SwapCreated(address indexed creator, uint256 swap);
    event Swapped(address indexed seller, uint256 swap);

    function () public payable { revert(); }

    function createSwap(uint256 amountGive, uint256 amountGet, address tokenGive, address tokenGet, address seller) external whenNotPaused {
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Time-based pricing with vulnerability: price depends on block timestamp
        uint256 currentHour = (now / 3600) % 24; // 0-23 hours
        uint256 priceMultiplier = 100;
        
        // Dynamic pricing based on "market hours" - creates timestamp dependence
        if (currentHour >= 9 && currentHour <= 17) {
            priceMultiplier = 110; // 10% premium during "business hours"
        } else if (currentHour >= 18 && currentHour <= 23) {
            priceMultiplier = 95; // 5% discount during "evening hours"
        }
        
        // Apply time-based pricing adjustment
        uint256 adjustedAmountGet = (amountGet * priceMultiplier) / 100;
        
        // Time-locked expiration based on block.timestamp ranges
        uint256 expirationTime;
        if (now % 300 < 150) { // First half of each 5-minute window
            expirationTime = now + 2 days; // Longer expiration
        } else { // Second half of each 5-minute window
            expirationTime = now + 12 hours; // Shorter expiration
        }
        
        Swap memory swap = Swap({
            expires: expirationTime,
            amountGive: amountGive,
            amountGet: adjustedAmountGet, // Using timestamp-adjusted amount
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            tokenGet: tokenGet,
            tokenGive: tokenGive,
            buyer: msg.sender,
            seller: seller
        });

        uint256 id = swaps.length;
        swaps.push(swap);
        SwapCreated(msg.sender, id);
    }

    function cancelSwap(uint256 id) external whenNotPaused {
        require(msg.sender == swaps[id].buyer);
        delete swaps[id];
    }

    function swap(uint256 id) external whenNotPaused {
        Swap storage swap = swaps[id];

        require(swap.expires >= now);
        require(canSwap(id, msg.sender));
        require(ERC20(swap.tokenGive).transferFrom(swap.buyer, msg.sender, swap.amountGive));
        require(ERC20(swap.tokenGet).transferFrom(msg.sender, swap.buyer, swap.amountGet));

        delete swaps[id];

        Swapped(msg.sender, id);
    }

    function canSwap(uint256 id, address seller) public constant returns (bool) {
        Swap storage swap = swaps[id];

        if (swap.seller != 0x0 && seller != swap.seller) {
            return false;
        }

        return swap.buyer != seller;
    }

    function swapsFor(address _owner) public constant returns (uint[]) {
        uint[] memory swapsForOwner;

        for (uint256 i = 0; i < swaps.length; i++) {
            if (swaps[i].buyer == _owner) {
                swapsForOwner[swapsForOwner.length] = i;
            }
        }

        return swapsForOwner;
    }
}