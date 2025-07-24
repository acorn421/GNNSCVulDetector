/*
 * ===== SmartInject Injection Details =====
 * Function      : createSwap
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 8 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding external calls to token contracts before state updates. The vulnerability works as follows:
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 
 * 1. **Transaction 1 (Setup)**: Attacker deploys a malicious token contract that implements ERC20 interface with malicious balanceOf() and approve() functions
 * 2. **Transaction 2 (Initial Call)**: Attacker calls createSwap() with their malicious token as tokenGive or uses a malicious contract as seller
 * 3. **Transaction 3+ (Reentrancy Chain)**: During the external calls (balanceOf or approve), the malicious contract reenters createSwap() multiple times, each time creating additional swaps with manipulated state
 * 
 * **State Persistence Vulnerability:**
 * - Each reentrant call increments swaps.length and creates new swaps
 * - The original swap ID calculation (uint256 id = swaps.length) becomes stale during reentrancy
 * - Multiple swaps get created with overlapping or manipulated IDs
 * - The persistent state in the swaps array enables exploitation across multiple transactions
 * 
 * **Exploitation Sequence:**
 * 1. Attacker creates malicious ERC20 token contract with reentrant balanceOf()
 * 2. Calls createSwap() with malicious token as tokenGive
 * 3. During balanceOf() check, malicious contract reenters createSwap() multiple times
 * 4. Each reentrant call creates additional swaps, potentially with different parameters
 * 5. State manipulation allows creation of favorable swap conditions across multiple transactions
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires deploying malicious contracts first (separate transaction)
 * - State accumulation in swaps array enables progressive exploitation
 * - Multiple reentrant calls build up exploitable state over several transactions
 * - The exploit leverages persistent storage changes that span multiple calls
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Validate token contracts before finalizing swap creation
        // This external call happens before state updates, enabling reentrancy
        require(ERC20(tokenGive).balanceOf(msg.sender) >= amountGive);
        require(ERC20(tokenGet).balanceOf(seller) >= amountGet);
        
        // External call to notify seller of pending swap - callback mechanism
        if (seller != address(0)) {
            // This allows seller contract to reenter and manipulate state
            ERC20(seller).approve(address(this), 0);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
        uint count = 0;
        for (uint256 i = 0; i < swaps.length; i++) {
            if (swaps[i].buyer == _owner) {
                count++;
            }
        }
        uint[] memory swapsForOwner = new uint[](count);
        count = 0;
        for (i = 0; i < swaps.length; i++) {
            if (swaps[i].buyer == _owner) {
                swapsForOwner[count] = i;
                count++;
            }
        }
        return swapsForOwner;
    }
}
