/*
 * ===== SmartInject Injection Details =====
 * Function      : extendSwapExpiration
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 8 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability creates a timestamp dependence issue where the extension mechanism relies on block.timestamp (now) for timing validation. An attacker can exploit this by: 1) First calling requestExtension() to set up the extension request, 2) Waiting for the delay period, 3) Calling extendSwapExpiration() at a strategically chosen time when miners might manipulate timestamps. The vulnerability is stateful as it requires the extensionRequests mapping to persist state between the two function calls, and multi-transaction as it requires both requestExtension() and extendSwapExpiration() to be called in sequence with a time delay.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    mapping(uint256 => uint256) public extensionRequests;
    mapping(uint256 => uint256) public extensionRequestTime;
    uint256 public constant EXTENSION_DELAY = 1 hours;
    
    function requestExtension(uint256 id, uint256 additionalTime) external whenNotPaused {
        require(msg.sender == swaps[id].buyer);
        require(swaps[id].expires > now);
        require(additionalTime > 0 && additionalTime <= 7 days);
        
        extensionRequests[id] = additionalTime;
        extensionRequestTime[id] = now;
    }
    
    function extendSwapExpiration(uint256 id) external whenNotPaused {
        require(msg.sender == swaps[id].buyer);
        require(extensionRequests[id] > 0);
        require(now >= extensionRequestTime[id] + EXTENSION_DELAY);
        
        swaps[id].expires = now + extensionRequests[id];
        
        delete extensionRequests[id];
        delete extensionRequestTime[id];
    }
    // === END FALLBACK INJECTION ===

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
