/*
 * ===== SmartInject Injection Details =====
 * Function      : addOrUpdateAccounts
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to `IAccountNotifier(_accountAddresses[cnt]).onAccountActivated()` during the loop iteration. This call occurs after setting `wasActive = true` and incrementing `accountslength`, but while still inside the loop processing multiple accounts. 
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * 1. **Transaction 1**: Owner calls `addOrUpdateAccounts` with an array containing a malicious contract address and other addresses
 * 2. **During Transaction 1**: When processing the malicious contract address, the external call `onAccountActivated()` is made
 * 3. **Reentrancy Attack**: The malicious contract's `onAccountActivated()` function calls back into `addOrUpdateAccounts` with the same address array
 * 4. **State Corruption**: The reentrant call processes accounts that have already been partially processed, leading to:
 *    - Duplicate entries in `accountIds` mapping (same address stored at multiple indices)
 *    - Incorrect `accountslength` counter (incremented multiple times for same accounts)
 *    - Potential array bounds violations in subsequent operations
 * 
 * **Why Multi-Transaction Dependent:**
 * - The vulnerability requires the attacker to first deploy a malicious contract with the `onAccountActivated()` function
 * - The attacker then needs to get the owner to call `addOrUpdateAccounts` including their malicious contract address
 * - The exploit unfolds through the sequence: owner call → external call → reentrant call
 * - State inconsistencies accumulate across these nested calls, creating persistent corruption
 * - The vulnerability leverages the fact that `wasActive` is set before the external call, allowing the reentrant call to process the same accounts again
 * 
 * This creates a classic stateful reentrancy where the vulnerability depends on the sequence of operations and state persistence between nested function calls.
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
        emit OwnerUpdate(owner, newOwner);
        owner = newOwner;
        newOwner = 0x0;
    }

    event OwnerUpdate(address _prevOwner, address _newOwner);
}

interface IAccountNotifier {
    function onAccountActivated(uint _level, uint _limit) external;
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

        for (uint cnt = 0; cnt < _accountAddresses.length; cnt++) {

            accounts[_accountAddresses[cnt]].active = true;
            accounts[_accountAddresses[cnt]].level = _levels[cnt];
            accounts[_accountAddresses[cnt]].limit = _limits[cnt];

            if (!accounts[_accountAddresses[cnt]].wasActive) {
                accounts[_accountAddresses[cnt]].wasActive = true;
                accountIds[accountslength] = _accountAddresses[cnt];
                accountslength++;
                // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                
                // VULNERABILITY: External call to notify account activation before finishing state updates
                // This allows reentrancy during the loop iteration
                if (isContract(_accountAddresses[cnt])) {
                    IAccountNotifier(_accountAddresses[cnt]).onAccountActivated(_levels[cnt], _limits[cnt]);
                }
                // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            }
        }
    }

    // Helper for contract detection compatible with Solidity <0.5
    function isContract(address _addr) internal view returns (bool is_contract) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
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
