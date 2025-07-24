/*
 * ===== SmartInject Injection Details =====
 * Function      : addAccountReader
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the new account reader contract before state updates. The vulnerability violates the checks-effects-interactions pattern by placing the external call before the state modifications. This creates a reentrancy window where the external contract can call back into the authentication manager while it's in an inconsistent state.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup)**: 
 * - Attacker deploys a malicious contract that implements the `onAccountReaderAdded` callback
 * - Attacker becomes an admin through legitimate means or exploits another vulnerability
 * 
 * **Transaction 2 (Exploitation)**:
 * - Attacker calls `addAccountReader` with their malicious contract address
 * - During the external call to `onAccountReaderAdded`, the malicious contract:
 *   - Re-enters the authentication manager (state is inconsistent)
 *   - Can manipulate admin privileges or exploit incomplete state transitions
 *   - The `accountReaderAddresses[_address]` is still false during the callback
 *   - Can potentially add multiple readers or manipulate the audit trail
 * 
 * **Transaction 3+ (Continued Exploitation)**:
 * - The attacker can continue exploiting the inconsistent state across multiple transactions
 * - Each subsequent call builds upon the corrupted state from previous transactions
 * - The vulnerability persists until the contract state is fully corrupted
 * 
 * **Why Multiple Transactions Are Required:**
 * 1. **State Accumulation**: The vulnerability requires building up corrupted state over multiple calls
 * 2. **Persistent Effects**: Each reentrancy event leaves the contract in a more vulnerable state
 * 3. **Complex Exploitation**: The attacker needs to establish malicious contracts first, then exploit them
 * 4. **Incremental Damage**: Each transaction can incrementally worsen the security posture
 * 
 * The vulnerability also fixes a bug in the original code where `adminAudit.length - 1` was used instead of `accountReaderAudit.length - 1` for the array index.
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
    function AuthenticationManager() {
        /* Set the first admin to be the person creating the contract */
        adminAddresses[msg.sender] = true;
        AdminAdded(0, msg.sender);
        adminAudit.length++;
        adminAudit[adminAudit.length - 1] = msg.sender;
    }

    /* Gets the contract version for validation */
    function contractVersion() constant returns(uint256) {
        // Admin contract identifies as 100YYYYMMDDHHMM
        return 100201707171503;
    }

    /* Gets whether or not the specified address is currently an admin */
    function isCurrentAdmin(address _address) constant returns (bool) {
        return adminAddresses[_address];
    }

    /* Gets whether or not the specified address has ever been an admin */
    function isCurrentOrPastAdmin(address _address) constant returns (bool) {
        for (uint256 i = 0; i < adminAudit.length; i++)
            if (adminAudit[i] == _address)
                return true;
        return false;
    }

    /* Gets whether or not the specified address is currently an account reader */
    function isCurrentAccountReader(address _address) constant returns (bool) {
        return accountReaderAddresses[_address];
    }

    /* Gets whether or not the specified address has ever been an admin */
    function isCurrentOrPastAccountReader(address _address) constant returns (bool) {
        for (uint256 i = 0; i < accountReaderAudit.length; i++)
            if (accountReaderAudit[i] == _address)
                return true;
        return false;
    }

    /* Adds a user to our list of admins */
    function addAdmin(address _address) {
        /* Ensure we're an admin */
        if (!isCurrentAdmin(msg.sender))
            throw;

        // Fail if this account is already admin
        if (adminAddresses[_address])
            throw;
        
        // Add the user
        adminAddresses[_address] = true;
        AdminAdded(msg.sender, _address);
        adminAudit.length++;
        adminAudit[adminAudit.length - 1] = _address;
    }

    /* Removes a user from our list of admins but keeps them in the history audit */
    function removeAdmin(address _address) {
        /* Ensure we're an admin */
        if (!isCurrentAdmin(msg.sender))
            throw;

        /* Don't allow removal of self */
        if (_address == msg.sender)
            throw;

        // Fail if this account is already non-admin
        if (!adminAddresses[_address])
            throw;

        /* Remove this admin user */
        adminAddresses[_address] = false;
        AdminRemoved(msg.sender, _address);
    }

    /* Adds a user/contract to our list of account readers */
    function addAccountReader(address _address) {
        /* Ensure we're an admin */
        if (!isCurrentAdmin(msg.sender))
            throw;

        // Fail if this account is already in the list
        if (accountReaderAddresses[_address])
            throw;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify the new account reader about their addition (vulnerable external call)
        // This creates a reentrancy window before state is fully updated
        if (_address.call(bytes4(keccak256("onAccountReaderAdded(address)")), msg.sender)) {
            // External call succeeded, continue with state updates
        }
        
        // Add the user - state updates happen AFTER external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        accountReaderAddresses[_address] = true;
        AccountReaderAdded(msg.sender, _address);
        accountReaderAudit.length++;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        accountReaderAudit[accountReaderAudit.length - 1] = _address;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    /* Removes a user/contracts from our list of account readers but keeps them in the history audit */
    function removeAccountReader(address _address) {
        /* Ensure we're an admin */
        if (!isCurrentAdmin(msg.sender))
            throw;

        // Fail if this account is already not in the list
        if (!accountReaderAddresses[_address])
            throw;

        /* Remove this admin user */
        accountReaderAddresses[_address] = false;
        AccountReaderRemoved(msg.sender, _address);
    }
}