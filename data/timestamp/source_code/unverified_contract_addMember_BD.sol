/*
 * ===== SmartInject Injection Details =====
 * Function      : addMember
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * The vulnerability introduces timestamp dependence by storing block.timestamp in the member.info field during member addition. This creates a stateful, multi-transaction vulnerability where:
 * 
 * 1. **Transaction 1**: addMember() stores current block.timestamp in member.info
 * 2. **Transaction 2+**: Other functions (like setMemberLevel, setMemberInfo) could validate membership based on this stored timestamp
 * 
 * The vulnerability enables multiple attack vectors:
 * - **Timestamp manipulation**: Miners can manipulate block.timestamp to bypass intended waiting periods
 * - **Race conditions**: Rapid successive calls can exploit timestamp-based validations
 * - **Temporal access bypass**: Functions checking membership validity based on stored timestamps become vulnerable
 * 
 * The stored timestamp persists between transactions, making this a genuine multi-transaction vulnerability where the state from the first addMember call affects the security of subsequent operations. An attacker would need to:
 * 1. First call addMember() to establish the timestamp state
 * 2. Then exploit timing dependencies in subsequent function calls that rely on this stored timestamp
 * 
 * This creates a realistic timestamp dependence vulnerability that requires multiple transactions to exploit and maintains the function's original behavior while introducing a subtle security flaw.
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Store member addition timestamp for security validation
        // Use block.timestamp as membership validation period
        member[_target].info = bytes32(block.timestamp);
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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