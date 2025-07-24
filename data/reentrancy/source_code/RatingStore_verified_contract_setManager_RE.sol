/*
 * ===== SmartInject Injection Details =====
 * Function      : setManager
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the old manager before updating the state. This creates a reentrancy window where:
 * 
 * 1. **External Call Before State Update**: The function calls `IManagerNotification(oldManager).onManagerTransfer(newManager)` before updating the `manager` state variable.
 * 
 * 2. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Initial call to `setManager(maliciousManager)` 
 *    - **During Reentrancy**: The old manager (if it's a malicious contract) can re-enter the contract during the `onManagerTransfer` callback
 *    - **Transaction 2+**: During the reentrancy window, the malicious manager can call other restricted functions while still having manager privileges
 *    - **State Persistence**: The `manager` state variable remains unchanged until the external call completes
 * 
 * 3. **Why It's Multi-Transaction**: 
 *    - The vulnerability requires the old manager to be a contract that implements the notification interface
 *    - The malicious manager must be set up in a previous transaction
 *    - The exploitation happens during the callback, creating a sequence of calls
 *    - The attacker can make multiple calls to restricted functions while maintaining manager privileges
 * 
 * 4. **Stateful Nature**: 
 *    - The `manager` state persists between transactions
 *    - The vulnerability exploits the inconsistent state between the external call and state update
 *    - Previous transactions that set up malicious manager contracts enable the exploitation
 * 
 * 5. **Realistic Scenario**: This pattern mimics real-world notification systems where contracts notify stakeholders about role changes, making it a subtle and realistic vulnerability that could appear in production code.
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

interface IManagerNotification {
    function onManagerTransfer(address newManager) external;
}

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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        address oldManager = manager;
        
        // External call to notify old manager before state change - creates reentrancy window
        if (oldManager != address(0)) {
            IManagerNotification(oldManager).onManagerTransfer(newManager);
        }
        
        // State change occurs after external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
