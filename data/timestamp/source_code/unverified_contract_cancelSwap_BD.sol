/*
 * ===== SmartInject Injection Details =====
 * Function      : cancelSwap
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by implementing a cooling-off period mechanism for swap cancellations. The vulnerability requires two separate transactions: 1) Initial transaction to register cancellation request with current timestamp, 2) Second transaction after 1 hour to actually cancel the swap. This creates timestamp dependence because miners can manipulate block.timestamp to either prevent legitimate cancellations (by keeping timestamps before the required delay) or allow premature cancellations (by advancing timestamps). The vulnerability is stateful as it stores cancellation request timestamps in the cancelationRequests mapping, persisting state between transactions. The exploit requires multiple transactions and accumulated state changes - attackers must first call cancelSwap to establish a timestamp, then manipulate subsequent block timestamps to bypass the time restriction. This makes it impossible to exploit in a single transaction, requiring coordination across multiple blocks.
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

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping(uint256 => uint256) public cancelationRequests;

    function cancelSwap(uint256 id) external whenNotPaused {
        require(msg.sender == swaps[id].buyer);
        
        // If this is the first cancellation request, store the timestamp
        if (cancelationRequests[id] == 0) {
            cancelationRequests[id] = now;
            return; // First call only registers the request
        }
        
        // For subsequent calls, check if cooling-off period has passed
        // Allow cancellation if at least 1 hour has passed since request
        require(now >= cancelationRequests[id] + 1 hours);
        
        delete swaps[id];
        delete cancelationRequests[id];
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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