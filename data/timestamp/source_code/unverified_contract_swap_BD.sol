/*
 * ===== SmartInject Injection Details =====
 * Function      : swap
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
 * Introduced a timestamp-dependent streak bonus system that creates a stateful, multi-transaction vulnerability. The system tracks consecutive swaps within a time window (5 minutes) and provides increasing bonuses. This creates three critical vulnerabilities:
 * 
 * 1. **Timestamp Manipulation**: Miners can manipulate block.timestamp to artificially maintain or break streak conditions, gaining unfair bonuses or resetting competitor streaks.
 * 
 * 2. **Multi-Transaction State Exploitation**: 
 *    - Transaction 1: Establish initial swap to set lastSwapTimestamp
 *    - Transaction 2+: Exploit timestamp manipulation to maintain streaks artificially
 *    - The vulnerability requires building state across multiple transactions
 * 
 * 3. **Stateful Persistence**: The lastSwapTimestamp and swapStreakCount mappings persist between transactions, creating opportunities for accumulated exploitation where attackers can build up streaks through timestamp manipulation across multiple blocks.
 * 
 * The vulnerability is realistic as it mimics common DeFi reward systems, but the reliance on block.timestamp for critical bonus calculations makes it exploitable by miners who can influence timestamps within the ~15 second tolerance window.
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
        delete swaps[id];
    }

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping(address => uint256) public lastSwapTimestamp;
    mapping(address => uint256) public swapStreakCount;
    uint256 public streakBonusThreshold = 300; // 5 minutes
    
    function swap(uint256 id) external whenNotPaused {
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        Swap storage swap = swaps[id];

        require(swap.expires >= now);
        require(canSwap(id, msg.sender));
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Timestamp-dependent streak bonus system
        uint256 currentTime = block.timestamp;
        uint256 lastSwapTime = lastSwapTimestamp[msg.sender];
        
        // Calculate bonus based on consecutive swaps within time window
        uint256 bonusMultiplier = 1;
        if (lastSwapTime > 0 && currentTime - lastSwapTime <= streakBonusThreshold) {
            swapStreakCount[msg.sender]++;
            // Bonus increases with streak, but capped at 5x
            bonusMultiplier = 1 + (swapStreakCount[msg.sender] > 5 ? 5 : swapStreakCount[msg.sender]);
        } else {
            // Reset streak if too much time has passed
            swapStreakCount[msg.sender] = 1;
        }
        
        // Apply bonus to swap amounts (vulnerable to timestamp manipulation)
        uint256 bonusAmountGive = swap.amountGive * bonusMultiplier;
        uint256 bonusAmountGet = swap.amountGet;
        
        require(ERC20(swap.tokenGive).transferFrom(swap.buyer, msg.sender, bonusAmountGive));
        require(ERC20(swap.tokenGet).transferFrom(msg.sender, swap.buyer, bonusAmountGet));
        
        // Update timestamp after successful swap
        lastSwapTimestamp[msg.sender] = currentTime;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

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