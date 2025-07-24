/*
 * ===== SmartInject Injection Details =====
 * Function      : bid
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability that manipulates bid calculations and dividend share allocations based on block.timestamp and block.blockhash. The vulnerability requires multiple transactions to exploit effectively because:
 * 
 * 1. **Timestamp-based Bonus System**: Added logic that gives bidders up to 20% bonus to their pot contribution based on `now % 100`, creating predictable patterns that can be exploited across multiple blocks.
 * 
 * 2. **Block Hash Randomness**: Introduced block.blockhash dependency that gives 10% pot bonuses when `block.blockhash(block.number - 1) % 10 == 0`, allowing miners to manipulate outcomes.
 * 
 * 3. **Time-based Dividend Multipliers**: Created timestamp-dependent dividend share calculations that give 20% more shares during the first half of each minute (`now % 60 < 30`).
 * 
 * 4. **Sequential Pattern Exploitation**: Added additional bonuses based on hour-based patterns that require accumulated state (`totalDividendShares > 0`) to unlock maximum benefits.
 * 
 * **Multi-Transaction Exploitation**:
 * - Transaction 1: Attacker observes timestamp patterns and makes initial bids to accumulate `totalDividendShares` state
 * - Transaction 2+: Attacker times subsequent bids to exploit favorable timestamp windows (first 30 seconds of minute, specific hour patterns)
 * - The exploitation requires state accumulation from previous transactions to unlock maximum timestamp-dependent bonuses
 * 
 * **Why Multi-Transaction is Required**:
 * - The `totalDividendShares > 0` condition requires previous transactions to build state
 * - Maximum exploitation requires timing multiple bids across different timestamp windows
 * - The vulnerability compounds over multiple transactions as state accumulates
 * - Single transaction cannot capture all timing-based advantages simultaneously
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
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====

        // Store timestamp-dependent state for bonus calculations
        uint _timestampSeed = now % 100;
        uint _blockBasedBonus = 0;
        
        // Multi-transaction vulnerability: accumulate timestamp-based bonuses
        if (_timestampSeed < 20) {
            _blockBasedBonus = msg.value.mul(_timestampSeed).div(100);
            _bidAmountToPot = _bidAmountToPot.add(_blockBasedBonus);
        }
        
        // Use block hash for additional randomness affecting pot distribution
        uint _blockHash = uint(block.blockhash(block.number - 1));
        if (_blockHash % 10 == 0) {
            _bidAmountToPot = _bidAmountToPot.mul(110).div(100); // 10% bonus
        }
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

        earnings[owner] = earnings[owner].add(_bidAmountToDeveloper);
        dividendFund = dividendFund.add(_bidAmountToDividendFund);
        pot = pot.add(_bidAmountToPot);
        Bid(now, msg.sender, msg.value, pot);

        if (msg.value >= _minLeaderAmount) {
            uint _dividendShares = msg.value.div(_minLeaderAmount);
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            
            // Timestamp-dependent dividend multiplier that requires state accumulation
            uint _timestampMultiplier = 100;
            if (now % 60 < 30) {
                _timestampMultiplier = 120; // 20% more shares during first half of minute
            }
            
            // Additional bonus based on sequential timestamp patterns
            if (totalDividendShares > 0 && (now - (now % 60)) % 3600 < 1800) {
                _timestampMultiplier = _timestampMultiplier.mul(110).div(100); // Additional 10% bonus
            }
            
            _dividendShares = _dividendShares.mul(_timestampMultiplier).div(100);
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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

    function withdrawDividends() public {
        require(dividendShares[msg.sender] > 0);
        uint _dividendShares = dividendShares[msg.sender];
        assert(_dividendShares <= totalDividendShares);
        uint _amount = dividendFund.mul(_dividendShares).div(totalDividendShares);
        assert(_amount <= this.balance);
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