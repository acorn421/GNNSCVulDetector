/*
 * ===== SmartInject Injection Details =====
 * Function      : initiateWithdrawal
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This injection introduces a stateful, multi-transaction reentrancy vulnerability. The vulnerability requires: 1) First transaction: User calls initiateWithdrawal() to set up withdrawal state, 2) Wait for delay period, 3) Second transaction: User calls executeWithdrawal() which is vulnerable to reentrancy due to external call before state cleanup. The vulnerability is stateful because it relies on pendingWithdrawals mapping persisting between transactions and the withdrawal delay mechanism.
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

    // === FALLBACK INJECTION: Reentrancy ===
    // Moving these to the contract scope, outside the function, to enable proper declarations
    mapping(address => uint) public pendingWithdrawals;
    mapping(address => uint) public withdrawalTimestamps;
    mapping(address => bool) public withdrawalInProgress;
    uint public constant WITHDRAWAL_DELAY = 24 hours;
    uint public contractBalance;
    
    modifier noReentrant() {
        require(!withdrawalInProgress[msg.sender], "Withdrawal already in progress");
        withdrawalInProgress[msg.sender] = true;
        _;
        withdrawalInProgress[msg.sender] = false;
    }
    
    function initiateWithdrawal(uint amount) public {
        require(amount > 0, "Amount must be greater than 0");
        require(contractBalance >= amount, "Insufficient contract balance");
        
        pendingWithdrawals[msg.sender] = amount;
        withdrawalTimestamps[msg.sender] = now;
        contractBalance = SafeMath.sub(contractBalance, amount);
    }
    
    function executeWithdrawal() public noReentrant {
        require(pendingWithdrawals[msg.sender] > 0, "No pending withdrawal");
        require(now >= withdrawalTimestamps[msg.sender] + WITHDRAWAL_DELAY, "Withdrawal delay not met");
        
        uint amount = pendingWithdrawals[msg.sender];
        
        // Vulnerable pattern: external call before state update
        (bool success, ) = msg.sender.call.value(amount)("");
        require(success, "Transfer failed");
        
        // State update after external call - vulnerable to reentrancy
        pendingWithdrawals[msg.sender] = 0;
        withdrawalTimestamps[msg.sender] = 0;
    }
    
    function deposit() public payable {
        contractBalance = SafeMath.add(contractBalance, msg.value);
    }
    // === END FALLBACK INJECTION ===

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
