/*
 * ===== SmartInject Injection Details =====
 * Function      : addMember
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the target address before the critical state update. The vulnerability works as follows:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `_target.call(bytes4(keccak256("onMemberAdded(address)")), msg.sender)` before the member level is set
 * 2. The call is made only if the target is a contract (has code)
 * 3. The call happens after the member ID is assigned but before the member level is set to Member
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract that implements `onMemberAdded(address)`
 * - The malicious contract's `onMemberAdded` function calls back to `addMember` with a different address
 * - During this reentrant call, the malicious contract can manipulate the memberCount and create inconsistent state
 * 
 * **Transaction 2+ (Exploitation):**
 * - The attacker exploits the inconsistent state created in Transaction 1
 * - Due to the reentrancy, multiple member IDs might be assigned to the same address
 * - The memberCount and memberAddress mappings become inconsistent
 * - The attacker can leverage this inconsistent state to:
 *   - Create duplicate members with different IDs
 *   - Bypass member existence checks in subsequent transactions
 *   - Manipulate the memberAddress array to point to unauthorized addresses
 * 
 * **Why Multi-Transaction:**
 * 1. **State Persistence**: The memberCount and member mappings are modified and persist between transactions
 * 2. **Accumulated Effects**: Each reentrant call during Transaction 1 accumulates state changes that affect future transactions
 * 3. **Delayed Exploitation**: The inconsistent state created in Transaction 1 enables unauthorized operations in subsequent transactions
 * 4. **Cross-Transaction Dependencies**: The vulnerability relies on the persistent state changes from previous transactions to be exploitable
 * 
 * **Realistic Integration:**
 * - The callback mechanism appears legitimate for notifying contracts about membership changes
 * - The external call pattern is common in DeFi and DAO contracts
 * - The vulnerability is subtle and could easily be missed in code reviews
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

    // Updated constructor to use 'constructor' keyword per warning
    constructor() public {
        owner = msg.sender;

        memberCount = 1;
        memberAddress[memberCount] = owner;
        member[owner] = Member(memberCount, MemberLevel.None, 0);
    }

    modifier onlyOwner {
        // left throw for Solidity 0.4.2 compatibility
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

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify the new member about their addition (vulnerable external call)
        // This call happens before the critical state update
        uint codeLength;
        assembly { codeLength := extcodesize(_target) }
        if (codeLength > 0) {
            // Call the member's onMemberAdded callback if it's a contract
            _target.call(bytes4(keccak256("onMemberAdded(address)")), msg.sender);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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