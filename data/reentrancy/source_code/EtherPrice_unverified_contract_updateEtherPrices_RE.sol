/*
 * ===== SmartInject Injection Details =====
 * Function      : updateEtherPrices
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
 * **Specific Changes Made:**
 * 
 * 1. **Added Reward System**: Introduced a reward mechanism that pays callers for updating prices, creating a financial incentive for price updates.
 * 
 * 2. **External Call Before State Update**: Added a `call` to transfer rewards to the caller BEFORE the critical state variables (ethPrice, levelPrice) are updated.
 * 
 * 3. **State Tracking Variables**: Added `isUpdating` flag and reward tracking to create persistent state that can be manipulated across transactions.
 * 
 * 4. **Reward Calculation Logic**: Added `calculateUpdateReward()` function that depends on historical state and timing.
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 
 * **Transaction 1 - Setup Phase:**
 * - Attacker calls `updateEtherPrices()` for the first time
 * - Receives first-time caller bonus reward
 * - During reward transfer (external call), attacker's malicious contract can re-enter
 * - During reentrancy, `ethPrice` is still the OLD value, but `isUpdating` is true
 * - Other contracts/functions may behave differently when `isUpdating` is true
 * 
 * **Transaction 2 - Exploitation Phase:**
 * - Attacker calls `updateEtherPrices()` again after some time has passed
 * - Now receives staleness reward based on time elapsed
 * - During reward transfer, attacker re-enters and can:
 *   - Call other functions in the contract that depend on `ethPrice`
 *   - Manipulate state while prices are inconsistent
 *   - Exploit the fact that `ethPrice` is old but `isUpdating` is true
 * 
 * **Transaction 3+ - Accumulation Phase:**
 * - Attacker can continue to call the function and accumulate rewards
 * - Each call creates a window where state is inconsistent
 * - The vulnerability compounds as the attacker builds up reward history
 * 
 * **Why Multiple Transactions Are Required:**
 * 
 * 1. **State Accumulation**: The vulnerability relies on building up `updateRewards[caller]` history over multiple calls to maximize reward calculation.
 * 
 * 2. **Timing Dependency**: The `staleness` reward depends on time elapsed between calls, requiring multiple transactions spaced over time.
 * 
 * 3. **Persistent State Exploitation**: The `isUpdating` flag and reward state persist between transactions, creating windows of vulnerability that can only be exploited through coordinated multi-transaction attacks.
 * 
 * 4. **Economic Incentive**: The reward system creates a legitimate reason for repeated calls, masking the malicious intent while building up the attack state.
 * 
 * The vulnerability is realistic because many DeFi protocols use similar reward mechanisms for oracle updates, and the external call pattern for payments is common in production code.
 */
pragma solidity >=0.4.23 <0.5.0;

library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");

        return c;
    }
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        return sub(a, b, "SafeMath: subtraction overflow");
    }

    function sub(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b <= a, errorMessage);
        uint256 c = a - b;

        return c;
    }
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }

        uint256 c = a * b;
        require(c / a == b, "SafeMath: multiplication overflow");

        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        return div(a, b, "SafeMath: division by zero");
    }

    function div(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b > 0, errorMessage);
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold

        return c;
    }

    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
        return mod(a, b, "SafeMath: modulo by zero");
    }
    
    function mod(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b != 0, errorMessage);
        return a % b;
    }
}

interface IMakerPriceFeed {
  function read() external view returns (bytes32);
}

contract EtherPrice {
    
    uint[22] public levelPrice;
    uint public regAmount;
    uint public ethPrice;

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => uint) public updateRewards;
    uint public totalRewardPool;
    bool public isUpdating;
    uint public lastUpdateTime;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    function updateEtherPrices() public{
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Get new ETH price from external source
        uint newEthPrice = getETHUSDPrice();
        
        // Calculate reward for caller before updating state
        uint reward = calculateUpdateReward(msg.sender);
        
        // VULNERABLE: External call to reward caller before state is fully updated
        if (reward > 0) {
            updateRewards[msg.sender] += reward;
            // Transfer reward to caller - this external call can be re-entered
            // FIX: Use correct syntax for .call in Solidity <0.6.0
            (bool success, ) = msg.sender.call.value(reward)("");
            require(success, "Reward transfer failed");
        }
        
        // Set updating flag to prevent some operations during update
        isUpdating = true;
        
        // Update the ETH price - this happens AFTER the external call
        ethPrice = newEthPrice;
        
        // Update registration amount
        regAmount = 0.1 ether;
        
        // Update level prices based on new ETH price
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        levelPrice[1] = SafeMath.div(5,ethPrice);
        levelPrice[2] = SafeMath.div(10,ethPrice);
        levelPrice[3] = SafeMath.div(20,ethPrice);
        levelPrice[4] = SafeMath.div(30,ethPrice);
        levelPrice[5] = SafeMath.div(40,ethPrice);
        levelPrice[6] = SafeMath.div(50,ethPrice);
        levelPrice[7] = SafeMath.div(75,ethPrice);
        levelPrice[8] = SafeMath.div(100,ethPrice);
        levelPrice[9] = SafeMath.div(125,ethPrice);
        levelPrice[10] = SafeMath.div(150,ethPrice);
        levelPrice[11] = SafeMath.div(200,ethPrice);
        levelPrice[12] = SafeMath.div(250,ethPrice);
        levelPrice[13] = SafeMath.div(300,ethPrice);
        levelPrice[14] = SafeMath.div(400,ethPrice);
        levelPrice[15] = SafeMath.div(500,ethPrice);
        levelPrice[16] = SafeMath.div(750,ethPrice);
        levelPrice[17] = SafeMath.div(1000,ethPrice);
        levelPrice[18] = SafeMath.div(1250,ethPrice);
        levelPrice[19] = SafeMath.div(1500,ethPrice);
        levelPrice[20] = SafeMath.div(2000,ethPrice);
        levelPrice[21] = SafeMath.div(3000,ethPrice);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Clear updating flag
        isUpdating = false;
        
        // Update reward pool for next caller
        totalRewardPool = SafeMath.sub(totalRewardPool, reward);
    }
    
    function calculateUpdateReward(address caller) internal view returns (uint) {
        // Calculate reward based on how stale the price is and caller's history
        if (updateRewards[caller] == 0) {
            return 0.01 ether; // First time caller bonus
        }
        
        // Calculate staleness reward
        uint staleness = block.timestamp - lastUpdateTime;
        uint stalenessReward = SafeMath.mul(staleness, 1000); // 1000 wei per second
        
        // Cap the reward
        uint maxReward = SafeMath.div(totalRewardPool, 10);
        return stalenessReward > maxReward ? maxReward : stalenessReward;
    }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    
  function getETHUSDPrice() public view returns (uint) {
    address ethUsdPriceFeed = 0x729D19f657BD0614b4985Cf1D82531c67569197B;
    return uint(
      IMakerPriceFeed(ethUsdPriceFeed).read()
    );
  }
  
  
}
