/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleUpdate
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence through a multi-transaction scheduled update system. An attacker can exploit this by: 1) First calling setUpdateScheduler() to become the scheduler, 2) Then calling scheduleUpdate() with a specific delay, 3) Waiting for miners to manipulate block timestamps, 4) Finally calling executeScheduledUpdate() when timestamp conditions are favorable. The vulnerability relies on the 'now' keyword (block.timestamp) for time-based logic across multiple state-changing transactions, allowing miners to influence when updates can be executed by manipulating block timestamps within the allowed drift range.
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

    uint public lastUpdateTime;
    uint public updateCooldown = 3600; // 1 hour cooldown
    address public updateScheduler;
    bool public updateScheduled = false;
    uint public scheduledUpdateTime;
    
    modifier onlyScheduler() {
        require(msg.sender == updateScheduler, "Only scheduler can call this");
        _;
    }
    
    function setUpdateScheduler(address _scheduler) public {
        require(updateScheduler == address(0), "Scheduler already set");
        updateScheduler = _scheduler;
    }
    
    function scheduleUpdate(uint _delayInSeconds) public onlyScheduler {
        require(!updateScheduled, "Update already scheduled");
        require(_delayInSeconds >= 60, "Delay must be at least 1 minute");
        
        scheduledUpdateTime = now + _delayInSeconds;
        updateScheduled = true;
    }
    
    function executeScheduledUpdate() public {
        require(updateScheduled, "No update scheduled");
        require(now >= scheduledUpdateTime, "Update time not reached yet");
        require(now - lastUpdateTime >= updateCooldown, "Cooldown period not met");
        
        updateEtherPrices();
        lastUpdateTime = now;
        updateScheduled = false;
        scheduledUpdateTime = 0;
    }
    
    function cancelScheduledUpdate() public onlyScheduler {
        require(updateScheduled, "No update to cancel");
        updateScheduled = false;
        scheduledUpdateTime = 0;
    }

    function updateEtherPrices() public{
        
        ethPrice=getETHUSDPrice();
        
        regAmount=0.1 ether;
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
    }
    
  function getETHUSDPrice() public view returns (uint) {
    address ethUsdPriceFeed = 0x729D19f657BD0614b4985Cf1D82531c67569197B;
    return uint(
      IMakerPriceFeed(ethUsdPriceFeed).read()
    );
  }
  
  
}
