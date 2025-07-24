/*
 * ===== SmartInject Injection Details =====
 * Function      : addOrUpdateAccounts
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
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability where:
 * 
 * 1. **State Dependency**: The vulnerability depends on the `wasActive` state from previous transactions - new accounts bypass the timing restriction, but existing accounts (marked as `wasActive` from prior calls) are subject to time-based update windows.
 * 
 * 2. **Multi-Transaction Exploitation**: 
 *    - **Transaction 1**: Call `addOrUpdateAccounts` to initially create accounts (sets `wasActive = true`)
 *    - **Transaction 2+**: Subsequent calls to update existing accounts are now subject to timestamp-dependent validation that can be manipulated
 * 
 * 3. **Timestamp Manipulation**: The vulnerability uses `block.timestamp` to create 5-minute time windows where account updates are allowed/denied based on a predictable pattern. Miners can manipulate `block.timestamp` within a 15-second window to either allow or block legitimate updates.
 * 
 * 4. **Realistic Attack Vector**: An attacker (potentially a miner) could:
 *    - Predict when legitimate account updates should fail based on timing windows
 *    - Manipulate `block.timestamp` to cause valid updates to be rejected
 *    - Force specific accounts to be updateable only during manipulated time windows
 * 
 * 5. **Business Logic Impact**: The timing restriction appears to implement a "cooling-off" period for account updates, but the predictable pattern and timestamp dependence make it exploitable across multiple transactions.
 */
/*

  Copyright 2017 Cofound.it.

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
pragma solidity ^0.4.13;

contract Owned {
    address public owner;
    address public newOwner;

    function Owned() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        assert(msg.sender == owner);
        _;
    }

    function transferOwnership(address _newOwner) public onlyOwner {
        require(_newOwner != owner);
        newOwner = _newOwner;
    }

    function acceptOwnership() public {
        require(msg.sender == newOwner);
        OwnerUpdate(owner, newOwner);
        owner = newOwner;
        newOwner = 0x0;
    }

    event OwnerUpdate(address _prevOwner, address _newOwner);
}

contract PriorityPassContract is Owned {

    struct Account {
    bool active;
    uint level;
    uint limit;
    bool wasActive;
    }

    uint public accountslength;
    mapping (uint => address) public accountIds;
    mapping (address => Account) public accounts;

    //
    // constructor
    //
    function PriorityPassContract() public { }

    //
    // @owner creates data for particular account
    // @param _accountAddress address for which we are setting the data
    // @param _level integer number that presents loyalty level
    // @param _limit integer number that presents limit within contribution can be made
    //
    function addNewAccount(address _accountAddress, uint _level, uint _limit) onlyOwner public {
        require(!accounts[_accountAddress].active);

        accounts[_accountAddress].active = true;
        accounts[_accountAddress].level = _level;
        accounts[_accountAddress].limit = _limit;

        if (!accounts[_accountAddress].wasActive) {
            accounts[_accountAddress].wasActive = true;
            accountIds[accountslength] = _accountAddress;
            accountslength++;
        }
    }

    //
    // @owner updates data for particular account
    // @param _accountAddress address for which we are setting the data
    // @param _level integer number that presents loyalty level
    // @param _limit integer number that presents limit within contribution can be made
    //
    function setAccountData(address _accountAddress, uint _level, uint _limit) onlyOwner public {
        require(accounts[_accountAddress].active);

        accounts[_accountAddress].level = _level;
        accounts[_accountAddress].limit = _limit;
    }

    //
    // @owner updates activity for particular account
    // @param _accountAddress address for which we are setting the data
    // @param _level bool value that presents activity level
    //
    function setActivity(address _accountAddress, bool _activity) onlyOwner public {
        accounts[_accountAddress].active = _activity;
    }

    //
    // @owner adds data for list of account
    // @param _accountAddresses array of accounts
    // @param _levels array of integer numbers corresponding to addresses order
    // @param _limits array of integer numbers corresponding to addresses order
    //
    function addOrUpdateAccounts(address[] _accountAddresses, uint[] _levels, uint[] _limits) onlyOwner public {
        require(_accountAddresses.length == _levels.length && _accountAddresses.length == _limits.length);

        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Store the timestamp when this batch operation was initiated
        uint batchTimestamp = block.timestamp;
        
        for (uint cnt = 0; cnt < _accountAddresses.length; cnt++) {
            
            // Check if this account has time-based restrictions
            if (accounts[_accountAddresses[cnt]].wasActive) {
                // Use a predictable time window based on block.timestamp for update eligibility
                // This creates a vulnerability where miners can manipulate timing
                uint updateWindow = (batchTimestamp / 300) * 300; // 5-minute windows
                uint accountSeed = uint(keccak256(abi.encodePacked(_accountAddresses[cnt]))) % 1000;
                
                // Time-based eligibility check - vulnerable to timestamp manipulation
                if ((updateWindow + accountSeed) % 2 == 0) {
                    // Account can only be updated in "even" time windows
                    require(block.timestamp >= updateWindow && block.timestamp < updateWindow + 300, "Account update not allowed in current time window");
                }
            }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

            accounts[_accountAddresses[cnt]].active = true;
            accounts[_accountAddresses[cnt]].level = _levels[cnt];
            accounts[_accountAddresses[cnt]].limit = _limits[cnt];

            if (!accounts[_accountAddresses[cnt]].wasActive) {
                accounts[_accountAddresses[cnt]].wasActive = true;
                accountIds[accountslength] = _accountAddresses[cnt];
                accountslength++;
            }
        }
    }

    //
    // @public asks about account loyalty level for the account
    // @param _accountAddress address to get data for
    // @returns level for the account
    //
    function getAccountLevel(address _accountAddress) public constant returns (uint) {
        return accounts[_accountAddress].level;
    }

    //
    // @public asks about account limit of contribution for the account
    // @param _accountAddress address to get data for
    //
    function getAccountLimit(address _accountAddress) public constant returns (uint) {
        return accounts[_accountAddress].limit;
    }

    //
    // @public asks about account being active or not
    // @param _accountAddress address to get data for
    //
    function getAccountActivity(address _accountAddress) public constant returns (bool) {
        return accounts[_accountAddress].active;
    }

    //
    // @public asks about data of an account
    // @param _accountAddress address to get data for
    //
    function getAccountData(address _accountAddress) public constant returns (uint, uint, bool) {
        return (accounts[_accountAddress].level, accounts[_accountAddress].limit, accounts[_accountAddress].active);
    }
}