/*
 * ===== SmartInject Injection Details =====
 * Function      : cancelSwap
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the seller's address before deleting the swap state. This creates a classic checks-effects-interactions pattern violation where:
 * 
 * 1. **Multi-Transaction Setup**: An attacker must first create a swap with a malicious contract as the seller (Transaction 1)
 * 2. **State Dependency**: The swap state must exist and persist between transactions for the vulnerability to be exploitable
 * 3. **Reentrancy Window**: When cancelSwap is called (Transaction 2), the external call to the seller occurs before the swap is deleted, allowing the malicious seller contract to reenter and manipulate state while the original swap still exists
 * 
 * The vulnerability requires multiple transactions because:
 * - Setup transaction needed to establish the malicious seller contract
 * - The actual exploit happens during the cancellation transaction
 * - State persistence between transactions is essential for the attack
 * - The malicious contract can reenter other functions or the same function while the original swap data remains intact
 * 
 * This is realistic as notification callbacks are common in DeFi protocols, and the vulnerability is subtle enough to pass initial code review while being genuinely exploitable.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Store reference to swap for callback
        Swap storage swap = swaps[id];
        
        // Notify callback contract about cancellation before state change
        if (swap.seller != address(0)) {
            // External call to seller's contract for cancellation notification
            (bool success, ) = swap.seller.call(
                abi.encodeWithSignature("onSwapCancelled(uint256,address)", id, msg.sender)
            );
            // Continue execution regardless of callback success
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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