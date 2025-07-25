/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawEarnings
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by violating the Checks-Effects-Interactions (CEI) pattern. The critical state update `earnings[msg.sender] = 0` has been moved to AFTER the external call `msg.sender.transfer(_amount)`, creating a multi-transaction vulnerability window.
 * 
 * **Specific Changes Made:**
 * 1. **Reordered statements**: Moved `earnings[msg.sender] = 0` from before the transfer to after the transfer
 * 2. **Preserved all other logic**: Function signature, checks, assertions, and event emission remain unchanged
 * 3. **Maintained functionality**: The function still performs its intended purpose of withdrawing earnings
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `withdrawEarnings()`, passes the require check, receives funds via transfer, but `earnings[msg.sender]` remains unchanged (still > 0)
 * 2. **Transaction 2**: Attacker calls `withdrawEarnings()` again, passes the require check again (since earnings still > 0), receives funds again
 * 3. **Transactions 3-N**: This process can continue until either the contract balance is insufficient or the attacker chooses to stop
 * 4. **Final Transaction**: Eventually the state update occurs, setting `earnings[msg.sender] = 0`
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability exploits the persistent state of the `earnings` mapping between transactions
 * - Each transaction sees the same non-zero earnings balance until the final state update
 * - The attacker must initiate separate transactions to repeatedly exploit the same earnings balance
 * - Cannot be exploited in a single atomic transaction because each withdrawal requires a separate external call and state persistence
 * - The stateful nature means the contract "remembers" the earnings balance across transaction boundaries, allowing repeated exploitation
 * 
 * **Realistic Attack Vector:**
 * An attacker with earnings in the contract can repeatedly call `withdrawEarnings()` in separate transactions, draining more funds than they're entitled to before the state is finally updated. This represents a classic multi-transaction reentrancy vulnerability that requires state persistence between calls to be effective.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        msg.sender.transfer(_amount);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        earnings[msg.sender] = 0;
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