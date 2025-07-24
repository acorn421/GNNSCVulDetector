/*
 * ===== SmartInject Injection Details =====
 * Function      : setPrice
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability by:
 * 
 * 1. **Timestamp-based Price Calculations**: The function now uses `block.timestamp` directly in price calculations, making the final price dependent on when the block is mined.
 * 
 * 2. **Time-based Adjustments**: Added logic that calculates price adjustments based on time differences using `block.timestamp % 300` (5-minute intervals) and applies hourly adjustment rates.
 * 
 * 3. **State-dependent Premium Logic**: For prices above 1000, an additional premium is added based on `block.timestamp % 100`, creating a modifier that depends on block timing.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: Creator calls `setPrice(1500)` when `block.timestamp` ends in a low number (e.g., timestamp % 100 = 5)
 * - **Transaction 2-N**: Users purchase tokens via the fallback function using the manipulated price
 * - **Exploitation**: A miner can manipulate the timestamp of the setPrice transaction to minimize the premium (choosing a timestamp where % 100 is small), then ensure subsequent purchase transactions occur at timestamps that maximize their advantage
 * 
 * **Why Multi-Transaction is Required:**
 * 1. The vulnerability requires the price to be set in one transaction, then exploited in subsequent purchase transactions
 * 2. The state changes (price with timestamp-based adjustments) persist between transactions
 * 3. Miners can manipulate the timing between the price-setting transaction and purchase transactions to create favorable conditions
 * 4. The time-based calculations create different outcomes depending on when transactions are included in blocks
 * 
 * This creates a realistic vulnerability where the price setting depends on block timing, and the effects compound across multiple transactions in the crowdsale.
 */
pragma solidity ^0.4.16;

interface Token {
    function transfer(address receiver, uint amount) public;
}

contract WRTCrowdsale {
    
    Token public tokenReward;
    address creator;
    address owner = 0x7f9c7CB1e4A8870849BF481D35EF088d6a456dbD;

    uint256 public startDate;
    uint256 public endDate;
    uint256 public price;

    event FundTransfer(address backer, uint amount, bool isContribution);

    function WRTCrowdsale() public {
        creator = msg.sender;
        startDate = 1514329200;     // 27/12/2017
        endDate = 1521586800;       // 20/03/2018
        price = 500;
        tokenReward = Token(0x973dc0c65B3eF4267394Cf9A1Fa1582827D9053f);
    }

    function setOwner(address _owner) public {
        require(msg.sender == creator);
        owner = _owner;      
    }

    function setCreator(address _creator) public {
        require(msg.sender == creator);
        creator = _creator;      
    }    

    function setStartDate(uint256 _startDate) public {
        require(msg.sender == creator);
        startDate = _startDate;      
    }

    function setEndDate(uint256 _endDate) public {
        require(msg.sender == creator);
        endDate = _endDate;      
    }

    function setPrice(uint256 _price) public {
        require(msg.sender == creator);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Store the timestamp when price change was requested
        uint256 priceChangeTimestamp = block.timestamp;
        
        // Apply gradual price adjustment based on time elapsed since last change
        if (price > 0) {
            uint256 timeDiff = priceChangeTimestamp - (priceChangeTimestamp % 300); // 5-minute blocks
            uint256 adjustment = (timeDiff * _price) / 3600; // Hourly adjustment rate
            price = _price + adjustment;
        } else {
            price = _price;
        }
        
        // Store the timestamp for future price calculations
        // This creates state that persists between transactions
        if (price > 1000) {
            // Use block.timestamp for premium pricing logic
            price = price + (block.timestamp % 100);
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }

    function sendToken(address receiver, uint amount) public {
        require(msg.sender == creator);
        tokenReward.transfer(receiver, amount);
        FundTransfer(receiver, amount, true);    
    }

    function () payable public {
        require(msg.value > 0);
        require(now > startDate);
        require(now < endDate);
        uint amount = msg.value * price;

        // Pre-sale 12/27   01/27
        if(now > startDate && now < 1517094000) {
            amount += amount / 2;
        }

        // Pre-ICO  02/01   02/28
        if(now > 1517439600 && now < 1519772400) {
            amount += amount / 3;
        }

        // ICO      03/10   03/20
        if(now > 1520636400 && now < 1521500400) {
            amount += amount / 4;
        }
        
        tokenReward.transfer(msg.sender, amount);
        FundTransfer(msg.sender, amount, true);
        owner.transfer(msg.value);
    }
}