/*
 * ===== SmartInject Injection Details =====
 * Function      : bid
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
 * 1. **Added External Call Before State Update**: Introduced a call to the previous leader's address before updating the leader state variable
 * 2. **Checks-Effects-Interactions Violation**: The external call occurs after the pot is updated but before the leader and deadline are updated, creating a window for reentrancy
 * 3. **State Dependency**: The vulnerability depends on the accumulated state from previous bidding transactions where a leader was established
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup Phase):**
 * - Attacker places initial bid to become leader
 * - Contract state: `leader = attacker_address, pot = initial_amount`
 * 
 * **Transaction 2 (Exploitation Phase):**
 * - Victim places higher bid triggering the vulnerability
 * - During the external call to attacker's address (previous leader), attacker can:
 *   - Re-enter the bid function multiple times
 *   - Each re-entry sees the updated pot value but outdated leader/deadline
 *   - Manipulate the bidding process by placing additional bids during the callback
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Accumulation**: The vulnerability only triggers when there's a previous leader from prior transactions - single transaction cannot establish this prerequisite state
 * 2. **Leadership Transition**: The attack requires at least one transaction to establish leadership, then another to trigger the vulnerable callback
 * 3. **Realistic Exploitation**: The attacker must first become a leader through legitimate bidding, then wait for another bidder to trigger the vulnerable notification mechanism
 * 
 * **Attack Vector:**
 * The attacker can deploy a malicious contract that:
 * - Places initial bid to become leader (Transaction 1)
 * - Implements fallback/receive function to re-enter bid() during the notification call (Transaction 2)
 * - Exploits the inconsistent state during reentrancy to manipulate pot distribution or leadership
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
                // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                // Notify the previous leader about being overtaken
                if (leader != address(0) && leader != msg.sender) {
                    // External call to previous leader before state update
                    (bool success, ) = leader.call.value(0)("");
                    // Continue regardless of call success
                }
                // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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