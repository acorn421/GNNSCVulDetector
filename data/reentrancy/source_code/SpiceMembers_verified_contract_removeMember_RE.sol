/*
 * ===== SmartInject Injection Details =====
 * Function      : removeMember
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the target member's contract before updating their member level. The vulnerability exploits the fact that during the external call, the member's level is still active (not yet set to None), allowing the target to re-enter other functions while maintaining their current permissions.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `_target.call(bytes4(keccak256("onMemberRemoval(address)")), msg.sender)` before the state update
 * 2. Used try-catch to handle callback failures gracefully
 * 3. Moved the state update `member[_target].level = MemberLevel.None;` to occur AFTER the external call
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1**: Attacker (with appropriate permissions) calls `removeMember()` on a malicious member contract
 * 2. **During External Call**: The malicious member contract's `onMemberRemoval` callback is triggered
 * 3. **Reentrancy Window**: While the callback executes, the member's level is still active (not None)
 * 4. **Exploitation**: The malicious contract can re-enter and call functions like `setMemberLevel()`, `setMemberInfo()`, or even `addMember()` while appearing as a valid member
 * 5. **State Persistence**: These re-entrant calls can modify persistent state that affects future transactions
 * 6. **Transaction 2+**: The modified state from the reentrancy can be leveraged in subsequent transactions
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability requires the initial `removeMember()` call to trigger the external callback
 * - The malicious contract must then make additional calls during the callback to exploit the temporary valid state
 * - The state changes made during reentrancy persist and can be exploited in future transactions
 * - The exploit cannot be contained within a single atomic transaction due to the callback mechanism and state persistence
 * 
 * **Realistic Integration:**
 * This vulnerability mimics real-world patterns where contracts notify members about status changes, making it a subtle and realistic security flaw that could appear in production code.
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

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify the member about their removal - member can implement onMemberRemoval callback
        // Vulnerability preserved using low-level call to external contract
        if (_target.call(bytes4(keccak256("onMemberRemoval(address)")), msg.sender)) {
            // Callback executed successfully
        } else {
            // Callback failed but continue with removal
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
