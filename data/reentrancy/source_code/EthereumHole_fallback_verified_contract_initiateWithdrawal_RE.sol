/*
 * ===== SmartInject Injection Details =====
 * Function      : initiateWithdrawal
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * This injection introduces a multi-transaction reentrancy vulnerability through a withdrawal system. The vulnerability requires multiple steps: 1) First, an attacker must initiate a withdrawal request, 2) Wait for the delay period, 3) Then call processWithdrawal() which makes an external call before updating state. The attacker can create a malicious contract that re-enters processWithdrawal() during the external call, allowing them to drain funds across multiple transactions. The state persists between transactions (withdrawalInitiated, pendingWithdrawals) making this a stateful vulnerability.
 */
pragma solidity ^0.4.19;

contract EthereumHole {
    using SafeMath for uint256;

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

    // Initial countdown duration at the start of each round
    uint public constant BASE_DURATION = 10 minutes;

    // Amount by which the countdown duration decreases per ether in the pot
    uint public constant DURATION_DECREASE_PER_ETHER = 5 minutes;

    // Minimum countdown duration
    uint public constant MINIMUM_DURATION = 5 minutes;
    
     // Minimum fraction of the pot required by a bidder to become the new leader
    uint public constant min_bid = 10000000000000 wei;

    // Current value of the pot
    uint public pot;

    // Address of the current leader
    address public leader;

    // Time at which the current round expires
    uint public deadline;
    
    // Is the game over?
    bool public gameIsOver;

    // === FALLBACK INJECTION: Reentrancy ===
    // Mapping to track pending withdrawals for each address
    mapping(address => uint256) public pendingWithdrawals;
    
    // Mapping to track withdrawal initiation status
    mapping(address => bool) public withdrawalInitiated;
    
    // Time delay for withdrawal processing (24 hours)
    uint public constant WITHDRAWAL_DELAY = 24 hours;
    
    // Mapping to track withdrawal request timestamps
    mapping(address => uint256) public withdrawalRequestTime;

    // Event for withdrawal initiation
    event WithdrawalInitiated(address indexed user, uint256 amount, uint256 requestTime);
    
    // Event for withdrawal completion
    event WithdrawalCompleted(address indexed user, uint256 amount);

    /**
     * @dev Initiates a withdrawal request for accumulated rewards
     * This function allows players to request withdrawal of their accumulated rewards
     * The withdrawal must be processed after a delay period
     */
    function initiateWithdrawal(uint256 _amount) public {
        require(_amount > 0);
        require(pendingWithdrawals[msg.sender] >= _amount);
        require(!withdrawalInitiated[msg.sender]);
        
        withdrawalInitiated[msg.sender] = true;
        withdrawalRequestTime[msg.sender] = now;
        
        WithdrawalInitiated(msg.sender, _amount, now);
    }

    /**
     * @dev Processes a withdrawal request after the delay period
     * VULNERABILITY: This function is vulnerable to reentrancy attacks
     * The external call happens before state updates, allowing recursive calls
     */
    function processWithdrawal() public {
        require(withdrawalInitiated[msg.sender]);
        require(now >= withdrawalRequestTime[msg.sender].add(WITHDRAWAL_DELAY));
        require(pendingWithdrawals[msg.sender] > 0);
        
        uint256 amount = pendingWithdrawals[msg.sender];
        
        // VULNERABLE: External call before state update
        // This allows for reentrancy attacks across multiple transactions
        msg.sender.call.value(amount)();
        
        // State updates happen after external call - VULNERABLE
        pendingWithdrawals[msg.sender] = 0;
        withdrawalInitiated[msg.sender] = false;
        withdrawalRequestTime[msg.sender] = 0;
        
        WithdrawalCompleted(msg.sender, amount);
    }
    // === END FALLBACK INJECTION ===

    function EthereumHole() public payable {
        require(msg.value > 0);
        gameIsOver = false;
        pot = msg.value;
        leader = msg.sender;
        deadline = computeDeadline();
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

    modifier endGameIfNeeded {
        if (now > deadline && !gameIsOver) {
            Winner(now, leader, pot, deadline);
            leader.transfer(pot);
            gameIsOver = true;
        }
        _;
    }

    function bid() public payable endGameIfNeeded {
        if (msg.value > 0 && !gameIsOver) {
            pot = pot.add(msg.value);
            if (msg.value >= min_bid) {
                leader = msg.sender;
                deadline = computeDeadline();
                NewLeader(now, leader, pot, deadline);
            }
        }
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
