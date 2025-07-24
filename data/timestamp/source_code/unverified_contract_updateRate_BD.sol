/*
 * ===== SmartInject Injection Details =====
 * Function      : updateRate
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability that requires state accumulation across multiple transactions to exploit. The vulnerability involves:
 * 
 * 1. **State Variables Added** (assumed to be declared in contract):
 *    - `uint256 public lastRateUpdate` - tracks last successful rate update timestamp
 *    - `uint256 public pendingRateUpdates` - tracks pending update initiation timestamp  
 *    - `uint256 public pendingRate` - accumulates pending rate changes
 *    - `uint256 public pendingBonus` - accumulates pending bonus changes
 * 
 * 2. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Owner calls updateRate during cooldown period, triggering emergency update mechanism with timestamp-based multiplier
 *    - **Transaction 2**: Owner calls updateRate again within 60 seconds, causing rate/bonus accumulation in pending state
 *    - **Transaction 3**: Owner calls updateRate after 60-second threshold, finalizing accumulated changes
 *    - **Transaction 4**: Attacker (if they have buy function access) can exploit the manipulated rates
 * 
 * 3. **Timestamp Dependence Vulnerabilities**:
 *    - `block.timestamp % 256` creates miner-manipulable multiplier (miners can adjust timestamp within ~15 second window)
 *    - Time-based thresholds (86400 seconds, 60 seconds) can be gamed through timestamp manipulation
 *    - Accumulation logic depends on precise timestamp differences that miners can influence
 *    - Emergency rate calculations use timestamp-derived multipliers that can be exploited
 * 
 * 4. **Stateful Nature**: 
 *    - Pending state persists between transactions
 *    - Rate accumulation requires multiple function calls to build up
 *    - Final exploitation requires sequence of setup transactions followed by usage
 * 
 * 5. **Realistic Scenario**: 
 *    - Appears as legitimate emergency rate update mechanism for ICO management
 *    - Cooldown periods and emergency overrides are common in DeFi protocols
 *    - Accumulation logic seems like reasonable averaging mechanism
 */
pragma solidity ^0.4.11;

contract ERC20 {
    function transfer(address to, uint tokens) public returns (bool success);
}

contract owned {
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
}


library SafeMath {
    function mul(uint a, uint b) internal pure returns (uint) {
        uint c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }

    function div(uint a, uint b) internal pure returns (uint) {
        // assert(b > 0); // Solidity automatically throws when dividing by 0
        uint c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold
        return c;
    }

    function sub(uint a, uint b) internal pure returns (uint) {
        assert(b <= a);
        return a - b;
    }

    function add(uint a, uint b) internal pure returns (uint) {
        uint c = a + b;
        assert(c >= a);
        return c;
    }

    function max64(uint64 a, uint64 b) internal pure returns (uint64) {
        return a >= b ? a : b;
    }

    function min64(uint64 a, uint64 b) internal pure returns (uint64) {
        return a < b ? a : b;
    }

    function max256(uint256 a, uint256 b) internal pure returns (uint256) {
        return a >= b ? a : b;
    }

    function min256(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
}


contract RocketsICO is owned {
    using SafeMath for uint;
    bool public ICOOpening = true;
    uint256 public USD;
    uint256 public ICORate = 1;
    uint256 public ICOBonus = 0;
    address public ROK = 0xca2660F10ec310DF91f3597574634A7E51d717FC;

    // ===== Added missing state variables for updateRate =====
    uint256 public lastRateUpdate;
    uint256 public pendingRateUpdates;
    uint256 public pendingRate;
    uint256 public pendingBonus;
    // =======================================================

    function updateUSD(uint256 usd) onlyOwner public {
        USD = usd;
    }

    function updateRate(uint256 rate, uint256 bonus) onlyOwner public {
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Emergency rate update mechanism - allows bypassing cooldown if timestamp delta is exploited
        if (block.timestamp - lastRateUpdate > 86400) { // 24 hour cooldown
            ICORate = rate;
            ICOBonus = bonus;
            lastRateUpdate = block.timestamp;
        } else {
            // Allow emergency updates with timestamp-based multiplier
            uint256 timestampMultiplier = (block.timestamp % 256) + 1; // Miner-manipulable
            uint256 emergencyRate = rate * timestampMultiplier / 100;
            uint256 emergencyBonus = bonus * timestampMultiplier / 100;
            
            // Store pending updates that accumulate over multiple transactions
            if (pendingRateUpdates == 0) {
                pendingRateUpdates = block.timestamp;
                pendingRate = emergencyRate;
                pendingBonus = emergencyBonus;
            } else {
                // Accumulate pending updates based on timestamp differences
                uint256 timeDiff = block.timestamp - pendingRateUpdates;
                if (timeDiff > 60) { // 1 minute threshold
                    ICORate = pendingRate;
                    ICOBonus = pendingBonus;
                    pendingRateUpdates = 0;
                    lastRateUpdate = block.timestamp;
                } else {
                    // Accumulate changes across multiple transactions
                    pendingRate = (pendingRate + emergencyRate) / 2;
                    pendingBonus = (pendingBonus + emergencyBonus) / 2;
                }
            }
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }

    function updateOpen(bool opening) onlyOwner public{
        ICOOpening = opening;
    }

    constructor() public {
    }

    function() public payable {
        buy();
    }

    function getAmountToBuy(uint256 ethAmount) public view returns (uint256){
        uint256 tokensToBuy;
        tokensToBuy = ethAmount.div(10 ** 18).mul(USD).mul(ICORate);
        if(ICOBonus > 0){
            uint256 bonusAmount;
            bonusAmount = tokensToBuy.div(100).mul(ICOBonus);
            tokensToBuy = tokensToBuy.add(bonusAmount);
        }
        return tokensToBuy;
    }

    function buy() public payable {
        require(ICOOpening == true);
        uint256 tokensToBuy;
        uint256 ethAmount = msg.value;
        tokensToBuy = ethAmount.div(10 ** 18).mul(USD).mul(ICORate);
        if(ICOBonus > 0){
            uint256 bonusAmount;
            bonusAmount = tokensToBuy.div(100).mul(ICOBonus);
            tokensToBuy = tokensToBuy.add(bonusAmount);
        }
        ERC20(ROK).transfer(msg.sender, tokensToBuy);
    }

    function withdrawROK(uint256 amount, address sendTo) onlyOwner public {
        ERC20(ROK).transfer(sendTo, amount);
    }

    function withdrawEther(uint256 amount, address sendTo) onlyOwner public {
        address(sendTo).transfer(amount);
    }

    function withdrawToken(ERC20 token, uint256 amount, address sendTo) onlyOwner public {
        require(token.transfer(sendTo, amount));
    }
}
