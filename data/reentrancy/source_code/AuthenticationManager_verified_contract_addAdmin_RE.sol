/*
 * ===== SmartInject Injection Details =====
 * Function      : addAdmin
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to validate admin eligibility before state updates. The vulnerability occurs because:
 * 
 * 1. **External Call Before State Updates**: Added `_address.call(abi.encodeWithSignature("validateAdmin()"))` before updating `adminAddresses` and `adminAudit`
 * 
 * 2. **Multi-Transaction Exploitation Pattern**:
 *    - **Transaction 1**: Attacker calls `addAdmin` with a malicious contract address
 *    - **During External Call**: The malicious contract's `validateAdmin()` function can re-enter `addAdmin` 
 *    - **State Inconsistency**: The first call hasn't updated state yet, so duplicate admin additions are possible
 *    - **Transaction 2**: Attacker exploits the inconsistent state between `adminAddresses` and `adminAudit`
 * 
 * 3. **Stateful Nature**: The vulnerability requires:
 *    - First transaction to trigger the external call and create inconsistent state
 *    - The state persists between transactions due to incomplete state updates
 *    - Second transaction can exploit the inconsistent admin privileges
 * 
 * 4. **Realistic Implementation**: The external validation call is a common pattern in production contracts for verifying address eligibility through external registries
 * 
 * 5. **Multi-Transaction Requirement**: The exploit cannot be completed in a single transaction because:
 *    - The reentrancy creates partially updated state
 *    - The attacker needs separate transactions to fully exploit the inconsistent admin state
 *    - The vulnerability manifests as admin privileges being granted while audit trail becomes corrupted across multiple calls
 */
pragma solidity ^0.4.11;

/* The authentication manager details user accounts that have access to certain priviledges and keeps a permanent ledger of who has and has had these rights. */
contract AuthenticationManager {
    /* Map addresses to admins */
    mapping (address => bool) adminAddresses;

    /* Map addresses to account readers */
    mapping (address => bool) accountReaderAddresses;

    /* Details of all admins that have ever existed */
    address[] adminAudit;

    /* Details of all account readers that have ever existed */
    address[] accountReaderAudit;

    /* Fired whenever an admin is added to the contract. */
    event AdminAdded(address addedBy, address admin);

    /* Fired whenever an admin is removed from the contract. */
    event AdminRemoved(address removedBy, address admin);

    /* Fired whenever an account-reader contract is added. */
    event AccountReaderAdded(address addedBy, address account);

    /* Fired whenever an account-reader contract is removed. */
    event AccountReaderRemoved(address removedBy, address account);

    /* When this contract is first setup we use the creator as the first admin */    
    constructor() public {
        /* Set the first admin to be the person creating the contract */
        adminAddresses[msg.sender] = true;
        emit AdminAdded(0, msg.sender);
        adminAudit.length++;
        adminAudit[adminAudit.length - 1] = msg.sender;
    }

    /* Gets the contract version for validation */
    function contractVersion() public constant returns(uint256) {
        // Admin contract identifies as 100YYYYMMDDHHMM
        return 100201707171503;
    }

    /* Gets whether or not the specified address is currently an admin */
    function isCurrentAdmin(address _address) public constant returns (bool) {
        return adminAddresses[_address];
    }

    /* Gets whether or not the specified address has ever been an admin */
    function isCurrentOrPastAdmin(address _address) public constant returns (bool) {
        for (uint256 i = 0; i < adminAudit.length; i++)
            if (adminAudit[i] == _address)
                return true;
        return false;
    }

    /* Gets whether or not the specified address is currently an account reader */
    function isCurrentAccountReader(address _address) public constant returns (bool) {
        return accountReaderAddresses[_address];
    }

    /* Gets whether or not the specified address has ever been an admin */
    function isCurrentOrPastAccountReader(address _address) public constant returns (bool) {
        for (uint256 i = 0; i < accountReaderAudit.length; i++)
            if (accountReaderAudit[i] == _address)
                return true;
        return false;
    }

    /* Adds a user to our list of admins */
    function addAdmin(address _address) public {
        /* Ensure we're an admin */
        if (!isCurrentAdmin(msg.sender))
            revert();

        // Fail if this account is already admin
        if (adminAddresses[_address])
            revert();

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Validate address through external registry before adding
        // This external call happens before state updates
        {
            // check if _address is a contract by checking code size
            uint256 codeLength;
            assembly { codeLength := extcodesize(_address) }
            if (codeLength > 0) {
                // Call external contract to validate admin eligibility
                // fallback to basic low-level call for 0.4.11 compatibility
                if (!_address.call(bytes4(keccak256("validateAdmin()")))) {
                    revert();
                }
            }
        }
        // Add the user (state updates happen after external call)
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        adminAddresses[_address] = true;
        emit AdminAdded(msg.sender, _address);
        adminAudit.length++;
        adminAudit[adminAudit.length - 1] = _address;
    }

    /* Removes a user from our list of admins but keeps them in the history audit */
    function removeAdmin(address _address) public {
        /* Ensure we're an admin */
        if (!isCurrentAdmin(msg.sender))
            revert();

        /* Don't allow removal of self */
        if (_address == msg.sender)
            revert();

        // Fail if this account is already non-admin
        if (!adminAddresses[_address])
            revert();

        /* Remove this admin user */
        adminAddresses[_address] = false;
        emit AdminRemoved(msg.sender, _address);
    }

    /* Adds a user/contract to our list of account readers */
    function addAccountReader(address _address) public {
        /* Ensure we're an admin */
        if (!isCurrentAdmin(msg.sender))
            revert();

        // Fail if this account is already in the list
        if (accountReaderAddresses[_address])
            revert();
        
        // Add the user
        accountReaderAddresses[_address] = true;
        emit AccountReaderAdded(msg.sender, _address);
        accountReaderAudit.length++;
        accountReaderAudit[accountReaderAudit.length - 1] = _address;
    }

    /* Removes a user/contracts from our list of account readers but keeps them in the history audit */
    function removeAccountReader(address _address) public {
        /* Ensure we're an admin */
        if (!isCurrentAdmin(msg.sender))
            revert();

        // Fail if this account is already not in the list
        if (!accountReaderAddresses[_address])
            revert();

        /* Remove this admin user */
        accountReaderAddresses[_address] = false;
        emit AccountReaderRemoved(msg.sender, _address);
    }
}
