/*
 * ===== SmartInject Injection Details =====
 * Function      : setDebug
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
 * Introduced timestamp dependence vulnerability by implementing time-based debug session management with a cooldown period. The function now uses block.timestamp for critical logic without proper validation, creating a stateful, multi-transaction vulnerability where:
 * 
 * 1. When enabling debug (_debug = true), the function stores the current block.timestamp in debugEnabledAt state variable
 * 2. When disabling debug (_debug = false), it requires a 300-second cooldown period to have passed since enablement
 * 3. The vulnerability exploits miners' ability to manipulate block timestamps within the allowed 15-second drift
 * 
 * **Multi-Transaction Exploitation Path:**
 * 1. **Transaction 1**: Manager calls setDebug(true) - stores current block.timestamp
 * 2. **Transaction 2**: Manager attempts to call setDebug(false) but may be blocked by cooldown
 * 3. **Exploitation**: Miners can manipulate timestamps across blocks to either:
 *    - Bypass the cooldown by setting future timestamps in Transaction 2
 *    - Extend debug sessions by setting past timestamps in Transaction 1
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability requires state persistence (debugEnabledAt) between transactions
 * - Exploitation depends on timestamp differences across multiple blocks
 * - Cannot be exploited in a single transaction since cooldown logic requires time passage
 * - State changes in Transaction 1 directly affect behavior in Transaction 2
 * 
 * This creates a realistic scenario where debug mode management becomes vulnerable to timestamp manipulation, potentially allowing unauthorized extension of debug privileges or bypassing intended security restrictions.
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
    }

    bool internal debug;
    uint internal debugEnabledAt; // <-- Declaration added
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
    constructor(address _manager, address _controller) public {
        manager = _manager;
        controller = _controller;
        debug = false;
        debugEnabledAt = 0;
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Time-based debug session management with cooldown
        if (_debug) {
            // Enable debug mode - store current timestamp
            debug = true;
            debugEnabledAt = block.timestamp;
        } else {
            // Disable debug mode - check if enough time has passed since last change
            require(block.timestamp >= debugEnabledAt + 300);
            debug = false;
            debugEnabledAt = 0;
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }

}
