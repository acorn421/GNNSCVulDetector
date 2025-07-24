/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawDividends
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through time-based dividend bonuses and withdrawal cooldowns. The vulnerability requires multiple transactions across different time periods to exploit:
 * 
 * **Specific Changes Made:**
 * 1. **Added State Variables**: `lastWithdrawalTime` mapping and timing constants for cooldown and bonus windows
 * 2. **Withdrawal Cooldown**: Users must wait 5 minutes between withdrawals, requiring multiple transactions over time
 * 3. **Lucky Window Bonus**: 50% bonus for withdrawals during specific 1-minute window each hour (1800-1860 seconds into each hour)
 * 4. **Timing Pattern Bonus**: Additional 25% bonus for withdrawing exactly 1-1.5 hours after previous withdrawal
 * 5. **Persistent State Tracking**: Stores withdrawal timestamps for future bonus calculations
 * 
 * **Multi-Transaction Exploitation:**
 * - **Transaction 1**: Initial withdrawal establishes baseline timestamp
 * - **Transaction 2**: Wait exactly 1-1.5 hours, then withdraw during lucky window for maximum bonus (75% total bonus)
 * - **Subsequent Transactions**: Repeat timing pattern to consistently exploit bonuses
 * 
 * **Why Multiple Transactions Required:**
 * - Cooldown period prevents single-transaction exploitation
 * - Bonus calculations depend on previous withdrawal timestamps stored in state
 * - Lucky window timing requires waiting for specific time periods
 * - Pattern bonuses only activate after establishing withdrawal history
 * 
 * **Vulnerability Mechanics:**
 * - Miners can manipulate `block.timestamp` within 15-second tolerance to hit lucky windows
 * - Attackers can study blockchain timing patterns to optimize withdrawal timing
 * - The vulnerability persists across transactions through state variable storage
 * - Combines timestamp manipulation with multi-transaction state accumulation
 */
pragma solidity ^0.4.19;

contract EtherHellDeluxe {
    using SafeMath for uint256;

    event NewRound(
        uint _timestamp,
        uint _round,
        uint _initialPot
    );

    event Bid(
        uint _timestamp,
        address _address,
        uint _amount,
        uint _newPot
    );

    event NewLeader(
        uint _timestamp,
        address _address,
        uint _newPot,
        uint _newDeadline
    );

    event Winner(
        uint _timestamp,
        address _address,
        uint _earnings,
        uint _deadline
    );

    event EarningsWithdrawal(
        uint _timestamp,
        address _address,
        uint _amount
    );

    event DividendsWithdrawal(
        uint _timestamp,
        address _address,
        uint _dividendShares,
        uint _amount,
        uint _newTotalDividendShares,
        uint _newDividendFund
    );

    // Initial countdown duration at the start of each round
    uint public constant BASE_DURATION = 90 minutes;

    // Amount by which the countdown duration decreases per ether in the pot
    uint public constant DURATION_DECREASE_PER_ETHER = 2 minutes;

    // Minimum countdown duration
    uint public constant MINIMUM_DURATION = 30 minutes;

    // Fraction of the previous pot used to seed the next pot
    uint public constant NEXT_POT_FRAC_TOP = 1;
    uint public constant NEXT_POT_FRAC_BOT = 2;

    // Minimum fraction of the pot required by a bidder to become the new leader
    uint public constant MIN_LEADER_FRAC_TOP = 5;
    uint public constant MIN_LEADER_FRAC_BOT = 1000;

    // Fraction of each bid put into the dividend fund
    uint public constant DIVIDEND_FUND_FRAC_TOP = 20;
    uint public constant DIVIDEND_FUND_FRAC_BOT = 100;

    // Fraction of each bid taken for the developer fee
    uint public constant DEVELOPER_FEE_FRAC_TOP = 5;
    uint public constant DEVELOPER_FEE_FRAC_BOT = 100;

    // Owner of the contract
    address owner;

    // Mapping from addresses to amounts earned
    mapping(address => uint) public earnings;

    // Mapping from addresses to dividend shares
    mapping(address => uint) public dividendShares;

    // Total number of dividend shares
    uint public totalDividendShares;

    // Value of the dividend fund
    uint public dividendFund;

    // Current round number
    uint public round;

    // Current value of the pot
    uint public pot;

    // Address of the current leader
    address public leader;

    // Time at which the current round expires
    uint public deadline;

    function EtherHellDeluxe() public payable {
        require(msg.value > 0);
        owner = msg.sender;
        round = 1;
        pot = msg.value;
        leader = owner;
        deadline = computeDeadline();
        NewRound(now, round, pot);
        NewLeader(now, leader, pot, deadline);
    }

    function computeDeadline() internal view returns (uint) {
        uint _durationDecrease = DURATION_DECREASE_PER_ETHER.mul(pot.div(1 ether));
        uint _duration;
        if (MINIMUM_DURATION.add(_durationDecrease) > BASE_DURATION) {
            _duration = MINIMUM_DURATION;
        } else {
            _duration = BASE_DURATION.sub(_durationDecrease);
        }
        return now.add(_duration);
    }

    modifier advanceRoundIfNeeded {
        if (now > deadline) {
            uint _nextPot = pot.mul(NEXT_POT_FRAC_TOP).div(NEXT_POT_FRAC_BOT);
            uint _leaderEarnings = pot.sub(_nextPot);
            Winner(now, leader, _leaderEarnings, deadline);
            earnings[leader] = earnings[leader].add(_leaderEarnings);
            round++;
            pot = _nextPot;
            leader = owner;
            deadline = computeDeadline();
            NewRound(now, round, pot);
            NewLeader(now, leader, pot, deadline);
        }
        _;
    }

    function bid() public payable advanceRoundIfNeeded {
        uint _minLeaderAmount = pot.mul(MIN_LEADER_FRAC_TOP).div(MIN_LEADER_FRAC_BOT);
        uint _bidAmountToDeveloper = msg.value.mul(DEVELOPER_FEE_FRAC_TOP).div(DEVELOPER_FEE_FRAC_BOT);
        uint _bidAmountToDividendFund = msg.value.mul(DIVIDEND_FUND_FRAC_TOP).div(DIVIDEND_FUND_FRAC_BOT);
        uint _bidAmountToPot = msg.value.sub(_bidAmountToDeveloper).sub(_bidAmountToDividendFund);

        earnings[owner] = earnings[owner].add(_bidAmountToDeveloper);
        dividendFund = dividendFund.add(_bidAmountToDividendFund);
        pot = pot.add(_bidAmountToPot);
        Bid(now, msg.sender, msg.value, pot);

        if (msg.value >= _minLeaderAmount) {
            uint _dividendShares = msg.value.div(_minLeaderAmount);
            dividendShares[msg.sender] = dividendShares[msg.sender].add(_dividendShares);
            totalDividendShares = totalDividendShares.add(_dividendShares);
            leader = msg.sender;
            deadline = computeDeadline();
            NewLeader(now, leader, pot, deadline);
        }
    }

    function withdrawEarnings() public advanceRoundIfNeeded {
        require(earnings[msg.sender] > 0);
        assert(earnings[msg.sender] <= this.balance);
        uint _amount = earnings[msg.sender];
        earnings[msg.sender] = 0;
        msg.sender.transfer(_amount);
        EarningsWithdrawal(now, msg.sender, _amount);
    }

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping(address => uint) public lastWithdrawalTime;
    uint public constant WITHDRAWAL_COOLDOWN = 300; // 5 minutes in seconds
    uint public constant LUCKY_WINDOW = 60; // 1 minute lucky window
    
    function withdrawDividends() public {
        require(dividendShares[msg.sender] > 0);
        
        // Check cooldown period
        require(now >= lastWithdrawalTime[msg.sender] + WITHDRAWAL_COOLDOWN, "Withdrawal cooldown active");
        
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        uint _dividendShares = dividendShares[msg.sender];
        assert(_dividendShares <= totalDividendShares);
        uint _amount = dividendFund.mul(_dividendShares).div(totalDividendShares);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based bonus calculation - vulnerable to timestamp manipulation
        uint _bonusMultiplier = 100; // Base 100%
        uint _timeWindow = now % 3600; // Current position in hour cycle
        
        // Lucky window: if withdrawal happens in specific time window, get bonus
        if (_timeWindow >= 1800 && _timeWindow <= 1800 + LUCKY_WINDOW) {
            _bonusMultiplier = 150; // 50% bonus
        }
        
        // Additional bonus based on last withdrawal timing pattern
        if (lastWithdrawalTime[msg.sender] > 0) {
            uint _timeSinceLastWithdrawal = now - lastWithdrawalTime[msg.sender];
            // Bonus for withdrawing exactly at optimal timing intervals
            if (_timeSinceLastWithdrawal >= 3600 && _timeSinceLastWithdrawal <= 3660) {
                _bonusMultiplier = _bonusMultiplier + 25; // Additional 25% bonus
            }
        }
        
        _amount = _amount.mul(_bonusMultiplier).div(100);
        assert(_amount <= this.balance);
        
        // Store withdrawal timestamp for future bonus calculations
        lastWithdrawalTime[msg.sender] = now;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        dividendShares[msg.sender] = 0;
        totalDividendShares = totalDividendShares.sub(_dividendShares);
        dividendFund = dividendFund.sub(_amount);
        msg.sender.transfer(_amount);
        DividendsWithdrawal(now, msg.sender, _dividendShares, _amount, totalDividendShares, dividendFund);
    }
}

/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {
    /**
    * @dev Multiplies two numbers, throws on overflow.
    */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }
        uint256 c = a * b;
        assert(c / a == b);
        return c;
    }

    /**
    * @dev Integer division of two numbers, truncating the quotient.
    */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        // assert(b > 0); // Solidity automatically throws when dividing by 0
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold
        return c;
    }

    /**
    * @dev Substracts two numbers, throws on overflow (i.e. if subtrahend is greater than minuend).
    */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b <= a);
        return a - b;
    }

    /**
    * @dev Adds two numbers, throws on overflow.
    */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }
}