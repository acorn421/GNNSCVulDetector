/*
 * ===== SmartInject Injection Details =====
 * Function      : swap
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Tracking**: Introduced `swapInProgress` mapping to track which swaps are currently being processed
 * 2. **External Call Before State Cleanup**: Restructured the code so that external calls (`transferFrom`) occur before the critical state cleanup (`delete swaps[id]`)
 * 3. **Vulnerable Callback Pattern**: Added a try-catch mechanism that creates a reentrancy window where the swap state persists during external calls
 * 4. **Multi-Transaction Exploitation Path**: The vulnerability requires multiple transactions to exploit:
 *    - Transaction 1: Attacker creates a malicious token contract
 *    - Transaction 2: Victim creates a swap involving the malicious token
 *    - Transaction 3: Attacker calls `swap()`, triggering reentrancy during `transferFrom`
 *    - During reentrancy: Attacker can call `swap()` again on the same ID since `delete swaps[id]` hasn't executed yet
 *    - The `swapInProgress` flag gets bypassed due to the reentrancy, allowing double-spending
 * 
 * The vulnerability is stateful because:
 * - It requires persistent state setup across multiple transactions
 * - The `swapInProgress` mapping maintains state between calls
 * - Exploitation depends on the timing of state changes across transaction boundaries
 * - The malicious token contract must be deployed and integrated before exploitation
 */
pragma solidity ^0.4.16;

contract ERC20 {
    
    string public name;
    function totalSupply() public constant returns (uint);
    function balanceOf(address _owner) public constant returns (uint);
    function allowance(address _owner, address _spender) public constant returns (uint);
    function transfer(address _to, uint _value) public returns (bool);
    function transferFrom(address _from, address _to, uint _value) public returns (bool);
    function approve(address _spender, uint _value) public returns (bool);

}

contract Ownable {

    address public owner;

    function Ownable() public {
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

    // Added missing declaration
    mapping(uint256 => bool) public swapInProgress;

    event SwapCreated(address indexed creator, uint256 swap);
    event Swapped(address indexed seller, uint256 swap);

    function () public payable { revert(); }

    function createSwap(uint256 amountGive, uint256 amountGet, address tokenGive, address tokenGet, address seller) external whenNotPaused {
        Swap memory swap = Swap({
            expires: now + 1 days,
            amountGive: amountGive,
            amountGet: amountGet,
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Track swap processing state to prevent double-processing
        require(!swapInProgress[id]);
        swapInProgress[id] = true;
        // External call that can trigger reentrancy
        require(ERC20(swap.tokenGive).transferFrom(swap.buyer, msg.sender, swap.amountGive));

        // Additional callback mechanism for token verification (vulnerable point)
        if (swap.tokenGet != address(0)) {
            // This external call happens before state cleanup, allowing reentrancy
            bool success = ERC20(swap.tokenGet).transferFrom(msg.sender, swap.buyer, swap.amountGet);
            if (!success) {
                swapInProgress[id] = false;
                revert();
            }
        }
        // State cleanup happens after external calls (vulnerable)
        delete swaps[id];
        swapInProgress[id] = false;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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
        // Fix: Allocate the array in memory with correct size
        uint count = 0;
        for (uint256 i = 0; i < swaps.length; i++) {
            if (swaps[i].buyer == _owner) {
                count++;
            }
        }
        uint[] memory swapsForOwner = new uint[](count);
        uint j = 0;
        for (i = 0; i < swaps.length; i++) {
            if (swaps[i].buyer == _owner) {
                swapsForOwner[j] = i;
                j++;
            }
        }
        return swapsForOwner;
    }
}
