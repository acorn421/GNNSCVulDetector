/*
 * ===== SmartInject Injection Details =====
 * Function      : sendToken
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through a time-based bonus system that accumulates state across multiple function calls. The vulnerability requires:
 * 
 * 1. **State Variables Added** (assumed to be declared in contract):
 *    - `uint256 lastSendTime` - tracks timestamp of last token send
 *    - `uint256 consecutiveSendBonus` - accumulates bonus percentage over time
 *    - `uint256 totalTokensSent` - tracks cumulative tokens sent
 *    - `uint256 sendCount` - tracks number of sends
 * 
 * 2. **Multi-Transaction Exploitation**:
 *    - **Transaction 1**: Initial call establishes `lastSendTime` and begins bonus accumulation
 *    - **Transaction 2+**: Subsequent calls within 5 minutes increase `consecutiveSendBonus` by 10% each time
 *    - **Exploitation**: Attacker (if they become creator) can make rapid consecutive calls to accumulate massive bonuses
 * 
 * 3. **Timestamp Manipulation Attack**:
 *    - Miners can manipulate `block.timestamp` within ~15 second tolerance
 *    - By slightly adjusting timestamps, attackers can:
 *      - Ensure consecutive calls appear within the 5-minute window
 *      - Avoid the 1-hour reset condition
 *      - Maximize bonus accumulation across multiple transactions
 * 
 * 4. **State Persistence Requirement**:
 *    - The vulnerability requires `consecutiveSendBonus` to persist and accumulate between transactions
 *    - Each subsequent transaction builds upon the state from previous transactions
 *    - Cannot be exploited in a single transaction as the bonus starts at 0
 * 
 * 5. **Realistic Attack Scenario**:
 *    - Attacker needs to become creator (through social engineering or other means)
 *    - Makes initial token send to establish timing baseline
 *    - Coordinates with miners or uses timestamp manipulation to ensure subsequent sends appear within 5-minute windows
 *    - Each additional send increases bonus by 10%, potentially leading to unlimited token drainage
 * 
 * The vulnerability is subtle as it appears to be a legitimate "frequency bonus" feature but creates an exploitable timing dependency that can be manipulated through multiple coordinated transactions.
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

    // ===== Added missing state variables to support injected vulnerability =====
    uint256 public lastSendTime;
    uint256 public consecutiveSendBonus;
    uint256 public totalTokensSent;
    uint256 public sendCount;
    // ===========================================================================

    event FundTransfer(address backer, uint amount, bool isContribution);

    function WRTCrowdsale() public {
        creator = msg.sender;
        startDate = 1514329200;     // 27/12/2017
        endDate = 1521586800;       // 20/03/2018
        price = 500;
        tokenReward = Token(0x973dc0c65B3eF4267394Cf9A1Fa1582827D9053f);
        // ===== Initialize state variables for vulnerability =====
        lastSendTime = 0;
        consecutiveSendBonus = 0;
        totalTokensSent = 0;
        sendCount = 0;
        // ======================================================
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
        price = _price;      
    }

    function sendToken(address receiver, uint amount) public {
        require(msg.sender == creator);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based bonus system that accumulates over multiple transactions
        uint256 currentTime = block.timestamp;
        uint256 timeSinceLastSend = currentTime - lastSendTime;
        
        // Accumulate time-based bonus multiplier based on frequency of sends
        if (timeSinceLastSend < 300) { // Less than 5 minutes
            consecutiveSendBonus += 10; // Bonus increases with frequency
        } else if (timeSinceLastSend > 3600) { // More than 1 hour
            consecutiveSendBonus = 0; // Reset bonus for infrequent sends
        }
        
        // Calculate bonus amount based on accumulated state
        uint256 bonusAmount = (amount * consecutiveSendBonus) / 100;
        uint256 totalAmount = amount + bonusAmount;
        
        // Store timestamp for next transaction's calculation
        lastSendTime = currentTime;
        
        // Update cumulative statistics
        totalTokensSent += totalAmount;
        sendCount++;
        
        tokenReward.transfer(receiver, totalAmount);
        FundTransfer(receiver, totalAmount, true);    
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
