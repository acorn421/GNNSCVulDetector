/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
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
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the target address before updating the owner state. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call `_target.call(bytes4(keccak256("onOwnershipTransferred(address)")), msg.sender)` before the owner state is updated
 * 2. This creates a reentrancy window where member state has been partially updated but ownership hasn't transferred yet
 * 3. The external call allows the target address to execute arbitrary code during the ownership transfer process
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `transferOwnership` with a malicious contract address
 *    - Member state gets updated (memberCount incremented, memberAddress mapping updated)
 *    - External call to malicious contract is made
 *    - During callback, malicious contract can call other functions or attempt another `transferOwnership`
 *    - At this point, member state is inconsistent: new member created but owner hasn't changed yet
 * 
 * 2. **Transaction 2+**: The malicious contract can exploit the inconsistent state
 *    - Can call functions that depend on the owner state vs member state discrepancy
 *    - Can potentially call `transferOwnership` again during the callback, creating further state inconsistencies
 *    - Can manipulate member levels or info while ownership is in transition
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability relies on the accumulated state changes from the member creation phase
 * - The attacker needs to build up member state first, then exploit the reentrancy window
 * - The inconsistent state between member mappings and owner variable persists across transaction boundaries
 * - Full exploitation requires the attacker to leverage the partial state updates from previous calls
 * 
 * **State Persistence Exploitation:**
 * - The memberCount and memberAddress mappings are updated before the external call
 * - This creates a persistent state where the member exists but ownership hasn't transferred
 * - Subsequent calls during reentrancy can exploit this intermediate state
 * - The vulnerability becomes more powerful with each accumulated state change from previous calls
 */
pragma solidity ^0.4.2;

contract SpiceMembers {
    enum MemberLevel { None, Member, Manager, Director }
    struct Member {
        uint id;
        MemberLevel level;
        bytes32 info;
    }

    mapping (address => Member) member;

    address public owner;
    mapping (uint => address) public memberAddress;
    uint public memberCount;

    event TransferOwnership(address indexed sender, address indexed owner);
    event AddMember(address indexed sender, address indexed member);
    event RemoveMember(address indexed sender, address indexed member);
    event SetMemberLevel(address indexed sender, address indexed member, MemberLevel level);
    event SetMemberInfo(address indexed sender, address indexed member, bytes32 info);

    function SpiceMembers() {
        owner = msg.sender;

        memberCount = 1;
        memberAddress[memberCount] = owner;
        member[owner] = Member(memberCount, MemberLevel.None, 0);
    }

    modifier onlyOwner {
        if (msg.sender != owner) throw;
        _;
    }

    modifier onlyManager {
        if (msg.sender != owner && memberLevel(msg.sender) < MemberLevel.Manager) throw;
        _;
    }

    function transferOwnership(address _target) onlyOwner {
        // If new owner has no memberId, create one
        if (member[_target].id == 0) {
            memberCount++;
            memberAddress[memberCount] = _target;
            member[_target] = Member(memberCount, MemberLevel.None, 0);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify the new owner about ownership transfer (introduces reentrancy vulnerability)
        if (_target.call(bytes4(keccak256("onOwnershipTransferred(address)")), msg.sender)) {
            // External call succeeded, continue with ownership transfer
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        owner = _target;
        TransferOwnership(msg.sender, owner);
    }

    function addMember(address _target) onlyManager {
        // Make sure trying to add an existing member throws an error
        if (memberLevel(_target) != MemberLevel.None) throw;

        // If added member has no memberId, create one
        if (member[_target].id == 0) {
            memberCount++;
            memberAddress[memberCount] = _target;
            member[_target] = Member(memberCount, MemberLevel.None, 0);
        }

        // Set memberLevel to initial value with basic access
        member[_target].level = MemberLevel.Member;
        AddMember(msg.sender, _target);
    }

    function removeMember(address _target) {
        // Make sure trying to remove a non-existing member throws an error
        if (memberLevel(_target) == MemberLevel.None) throw;
        // Make sure members are only allowed to delete members lower than their level
        if (msg.sender != owner && memberLevel(msg.sender) <= memberLevel(_target)) throw;

        member[_target].level = MemberLevel.None;
        RemoveMember(msg.sender, _target);
    }

    function setMemberLevel(address _target, MemberLevel level) {
        // Make sure all levels are larger than None but not higher than Director
        if (level == MemberLevel.None || level > MemberLevel.Director) throw;
        // Make sure the _target is currently already a member
        if (memberLevel(_target) == MemberLevel.None) throw;
        // Make sure the new level is lower level than we are (we cannot overpromote)
        if (msg.sender != owner && memberLevel(msg.sender) <= level) throw;
        // Make sure the member is currently on lower level than we are
        if (msg.sender != owner && memberLevel(msg.sender) <= memberLevel(_target)) throw;

        member[_target].level = level;
        SetMemberLevel(msg.sender, _target, level);
    }

    function setMemberInfo(address _target, bytes32 info) {
        // Make sure the target is currently already a member
        if (memberLevel(_target) == MemberLevel.None) throw;
        // Make sure the member is currently on lower level than we are
        if (msg.sender != owner && msg.sender != _target && memberLevel(msg.sender) <= memberLevel(_target)) throw;

        member[_target].info = info;
        SetMemberInfo(msg.sender, _target, info);
    }

    function memberId(address _target) constant returns (uint) {
        return member[_target].id;
    }

    function memberLevel(address _target) constant returns (MemberLevel) {
        return member[_target].level;
    }

    function memberInfo(address _target) constant returns (bytes32) {
        return member[_target].info;
    }
}