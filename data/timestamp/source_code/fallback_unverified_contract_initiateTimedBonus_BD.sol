/*
 * ===== SmartInject Injection Details =====
 * Function      : initiateTimedBonus
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue that requires multiple transactions to exploit. First, an attacker needs to call initiateTimedBonus() to set up the bonus window, then call claimTimedBonus() within the time window. The vulnerability relies on block.timestamp (now) which can be manipulated by miners within certain bounds. A malicious miner could potentially extend their bonus claiming window by manipulating timestamps, allowing them to claim bonuses even when they should have expired. The state persists between transactions through the bonusEligibilityTime and bonusInitiated mappings, making this a stateful, multi-transaction vulnerability.
 */
pragma solidity ^0.4.11;

/*  Copyright 2017 GoInto, LLC

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

/**
 * Storage contract for Etherep to store ratings and score data.  It's been 
 * separated from the main contract because this is much less likely to change
 * than the other parts.  It would allow for upgrading the main contract without
 * losing data.
 */
contract RatingStore {

    struct Score {
        bool exists;
        int cumulativeScore;
        uint totalRatings;
    } // <-- Added missing closing curly brace for struct

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // Mapping to track bonus eligibility windows
    mapping (address => uint) internal bonusEligibilityTime;
    mapping (address => bool) internal bonusInitiated;
    
    /**
     * Initiate a timed bonus period for an address
     * @param target The address to initiate bonus for
     * @param bonusWindow Time window in seconds for bonus eligibility
     */
    function initiateTimedBonus(address target, uint bonusWindow) external restricted {
        require(bonusWindow > 0 && bonusWindow <= 86400); // Max 24 hours
        bonusEligibilityTime[target] = now + bonusWindow;
        bonusInitiated[target] = true;
        if (debug) {
            Debug("Bonus initiated for target");
        }
    }
    
    /**
     * Claim the timed bonus if within eligibility window
     * @param target The address claiming the bonus
     */
    function claimTimedBonus(address target) external restricted {
        require(bonusInitiated[target] == true);
        require(now <= bonusEligibilityTime[target]); // Vulnerable to timestamp manipulation
        
        if (!scores[target].exists) {
            scores[target] = Score(true, 0, 0);
        }
        
        // Apply bonus - add 100 points to cumulative score
        scores[target].cumulativeScore += 100;
        
        // Reset bonus state
        bonusInitiated[target] = false;
        bonusEligibilityTime[target] = 0;
        
        if (debug) {
            Debug("Timed bonus claimed successfully");
        }
    }
    
    /**
     * Check if bonus is still claimable for an address
     * @param target The address to check
     * @return bool Whether bonus is claimable
     * @return uint Time remaining for bonus claim
     */
    function getBonusStatus(address target) external constant returns (bool, uint) {
        if (!bonusInitiated[target]) {
            return (false, 0);
        }
        
        if (now > bonusEligibilityTime[target]) {
            return (false, 0);
        }
        
        return (true, bonusEligibilityTime[target] - now);
    }
    // === END FALLBACK INJECTION ===

    bool internal debug;
    mapping (address => Score) internal scores;
    // The manager with full access
    address internal manager;
    // The contract that has write accees
    address internal controller;

    /// Events
    event Debug(string message);

    /**
     * Only the manager or controller can use this method
     */
    modifier restricted() { 
        require(msg.sender == manager || tx.origin == manager || msg.sender == controller);
        _; 
    }

    /**
     * Only a certain address can use this modified method
     * @param by The address that can use the method
     */
    modifier onlyBy(address by) { 
        require(msg.sender == by);
        _; 
    }

    /**
     * Constructor
     * @param _manager The address that has full access to the contract
     * @param _controller The contract that can make write calls to this contract
     */
    function RatingStore(address _manager, address _controller) {
        manager = _manager;
        controller = _controller;
        debug = false;
    }

    /**
     * Set a Score
     * @param target The address' score we're setting
     * @param cumulative The cumulative score for the address
     * @param total Total individual ratings for the address
     * @return success If the set was completed successfully
     */
    function set(address target, int cumulative, uint total) external restricted {
        if (!scores[target].exists) {
            scores[target] = Score(true, 0, 0);
        }
        scores[target].cumulativeScore = cumulative;
        scores[target].totalRatings = total;
    }

    /**
     * Add a rating
     * @param target The address' score we're adding to
     * @param wScore The weighted rating to add to the score
     * @return success
     */
    function add(address target, int wScore) external restricted {
        if (!scores[target].exists) {
            scores[target] = Score(true, 0, 0);
        }
        scores[target].cumulativeScore += wScore;
        scores[target].totalRatings += 1;
    }

    /**
     * Get the score for an address
     * @param target The address' score to return
     * @return cumulative score
     * @return total ratings
     */
    function get(address target) external constant returns (int, uint) {
        if (scores[target].exists == true) {
            return (scores[target].cumulativeScore, scores[target].totalRatings);
        } else {
            return (0,0);
        }
    }

    /**
     * Reset an entire score storage
     * @param target The address we're wiping clean
     */
    function reset(address target) external onlyBy(manager) {
        scores[target] = Score(true, 0,0);
    }

    /**
     * Return the manager
     * @return address The manager address
     */
    function getManager() external constant returns (address) {
        return manager;
    }

    /**
     * Change the manager
     * @param newManager The address we're setting as manager
     */
    function setManager(address newManager) external onlyBy(manager) {
        manager = newManager;
    }

    /**
     * Return the controller
     * @return address The manager address
     */
    function getController() external constant returns (address) {
        return controller;
    }

    /**
     * Change the controller
     * @param newController The address we're setting as controller
     */
    function setController(address newController) external onlyBy(manager) {
        controller = newController;
    }

    /**
     * Return the debug setting
     * @return bool debug
     */
    function getDebug() external constant returns (bool) {
        return debug;
    }

    /**
     * Set debug
     * @param _debug The bool value debug should be set to
     */
    function setDebug(bool _debug) external onlyBy(manager) {
        debug = _debug;
    }

}