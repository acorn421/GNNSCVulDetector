/*
 * ===== SmartInject Injection Details =====
 * Function      : addAccountReader
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through time-based access controls. The function now relies on block.timestamp for critical security decisions and maintains persistent state through adminLastActionTime mapping. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added time-slot calculation using `(block.timestamp / 300) % 24` for 5-minute windows over 2 hours
 * 2. Introduced `adminLastActionTime` state variable to track admin activity timestamps
 * 3. Implemented time-based restrictions during "sensitive hours" (slots 20-4)
 * 4. Added a 1-hour window check for admin activity during restricted periods
 * 5. Updated admin timestamps on each successful call
 * 
 * **Multi-Transaction Exploitation Path:**
 * 1. **Transaction 1**: Admin calls function during normal hours to establish initial `adminLastActionTime`
 * 2. **Wait Period**: Attacker waits for block.timestamp to enter restricted time window (slots 20-4)
 * 3. **Transaction 2**: Attacker (if they gained admin privileges) or malicious admin can exploit the time-based logic by manipulating block.timestamp through mining control or by timing transactions precisely
 * 4. **Transaction 3+**: Continue exploitation during the time window when restrictions are bypassed
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires establishing initial state (`adminLastActionTime`) in one transaction
 * - The time-based restrictions only become exploitable after the timestamp state is set
 * - Attackers need to wait for or manipulate block.timestamp to reach exploitable time windows
 * - The 1-hour window check creates a dependency on previous transaction timestamps
 * 
 * **Realistic Timestamp Dependence Patterns:**
 * - Uses block.timestamp for critical access control decisions
 * - Stores timestamp state that affects future transaction behavior  
 * - Creates time-based race conditions across multiple blocks
 * - Implements "security" features that actually introduce vulnerabilities
 * - Follows common patterns seen in real-world smart contract timestamp bugs
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

    // Map admins to their last action time for timestamp dependence logic
    mapping(address => uint256) adminLastActionTime;

    /* Fired whenever an admin is added to the contract. */
    event AdminAdded(address addedBy, address admin);

    /* Fired whenever an admin is removed from the contract. */
    event AdminRemoved(address removedBy, address admin);

    /* Fired whenever an account-reader contract is added. */
    event AccountReaderAdded(address addedBy, address account);

    /* Fired whenever an account-reader contract is removed. */
    event AccountReaderRemoved(address removedBy, address account);

    /* When this contract is first setup we use the creator as the first admin */    
    function AuthenticationManager() public {
        /* Set the first admin to be the person creating the contract */
        adminAddresses[msg.sender] = true;
        AdminAdded(0, msg.sender);
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
    function removeAdmin(address _address) public {
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
    function addAccountReader(address _address) public {
        /* Ensure we're an admin */
        if (!isCurrentAdmin(msg.sender))
            throw;

        // Fail if this account is already in the list
        if (accountReaderAddresses[_address])
            throw;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Enhanced security: Time-based access control to prevent rapid privilege escalation
        // Only allow adding readers during specific time windows for better security
        uint256 currentTimeSlot = (block.timestamp / 300) % 24; // 5-minute slots over 2 hours
        
        // Store the admin's last action timestamp for audit and security purposes
        if (adminLastActionTime[msg.sender] == 0) {
            adminLastActionTime[msg.sender] = block.timestamp;
        }
        
        // Security feature: Prevent adding readers during sensitive time periods
        // This helps prevent automated attacks during off-hours
        if (currentTimeSlot >= 20 || currentTimeSlot <= 4) {
            // During restricted hours, only allow if admin has been active recently
            if (block.timestamp - adminLastActionTime[msg.sender] > 3600) { // 1 hour window
                throw;
            }
        }
        
        // Update admin's last action timestamp
        adminLastActionTime[msg.sender] = block.timestamp;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        // Add the user
        accountReaderAddresses[_address] = true;
        AccountReaderAdded(msg.sender, _address);
        accountReaderAudit.length++;
        accountReaderAudit[accountReaderAudit.length - 1] = _address;
    }

    /* Removes a user/contracts from our list of account readers but keeps them in the history audit */
    function removeAccountReader(address _address) public {
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
