/*
 * ===== SmartInject Injection Details =====
 * Function      : setMemberLevel
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
 * Introduced a timestamp-dependent promotion cooldown mechanism that creates a stateful, multi-transaction vulnerability. The vulnerability manifests through the use of block.timestamp for critical access control logic without proper validation. 
 * 
 * **Specific Changes Made:**
 * 1. Added a `lastPromotionTime` field tracking mechanism using `member[_target].lastPromotionTime`
 * 2. Implemented a 24-hour cooldown period using `block.timestamp - lastPromotionTime < 86400`
 * 3. Made promotions depend on block.timestamp values for critical authorization decisions
 * 4. Created persistent state that accumulates across transactions
 * 
 * **Multi-Transaction Exploitation:**
 * The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1**: An attacker initiates a promotion request when block.timestamp is manipulable or predictable
 * **Transaction 2**: The attacker waits for or influences block timestamp progression
 * **Transaction 3**: The attacker can bypass the cooldown through timestamp manipulation techniques such as:
 * - Mining manipulation where miners can adjust timestamps within consensus rules
 * - Exploiting timestamp dependencies during network conditions where block times vary
 * - Using the 15-second timestamp tolerance in Ethereum to manipulate timing windows
 * 
 * **Why Multi-Transaction Required:**
 * 1. **State Accumulation**: The vulnerability depends on the `lastPromotionTime` state persisting between transactions
 * 2. **Timing Dependencies**: Exploiting timestamp manipulation requires waiting for or influencing block progression
 * 3. **Cooldown Bypass**: The exploit involves manipulating timing across multiple blocks to bypass intended access controls
 * 4. **Authorization Chain**: The vulnerability affects future authorization decisions based on accumulated timestamp state
 * 
 * **Real-World Exploitation Scenario:**
 * An attacker could coordinate with miners or exploit network conditions to manipulate block timestamps, allowing rapid successive promotions that should be prevented by the cooldown mechanism. This creates unauthorized privilege escalation through timing manipulation across multiple transactions.
 */
pragma solidity ^0.4.2;

contract SpiceMembers {
    enum MemberLevel { None, Member, Manager, Director }
    struct Member {
        uint id;
        MemberLevel level;
        bytes32 info;
        uint lastPromotionTime; // Added for promotion cooldown
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

    function SpiceMembers() public {
        owner = msg.sender;
        memberCount = 1;
        memberAddress[memberCount] = owner;
        member[owner] = Member(memberCount, MemberLevel.None, 0, 0);
    }

    modifier onlyOwner {
        if (msg.sender != owner) revert();
        _;
    }

    modifier onlyManager {
        if (msg.sender != owner && memberLevel(msg.sender) < MemberLevel.Manager) revert();
        _;
    }

    function transferOwnership(address _target) public onlyOwner {
        // If new owner has no memberId, create one
        if (member[_target].id == 0) {
            memberCount++;
            memberAddress[memberCount] = _target;
            member[_target] = Member(memberCount, MemberLevel.None, 0, 0);
        }
        owner = _target;
        emit TransferOwnership(msg.sender, owner);
    }

    function addMember(address _target) public onlyManager {
        // Make sure trying to add an existing member throws an error
        if (memberLevel(_target) != MemberLevel.None) revert();
        // If added member has no memberId, create one
        if (member[_target].id == 0) {
            memberCount++;
            memberAddress[memberCount] = _target;
            member[_target] = Member(memberCount, MemberLevel.None, 0, 0);
        }
        // Set memberLevel to initial value with basic access
        member[_target].level = MemberLevel.Member;
        emit AddMember(msg.sender, _target);
    }

    function removeMember(address _target) public {
        // Make sure trying to remove a non-existing member throws an error
        if (memberLevel(_target) == MemberLevel.None) revert();
        // Make sure members are only allowed to delete members lower than their level
        if (msg.sender != owner && memberLevel(msg.sender) <= memberLevel(_target)) revert();
        member[_target].level = MemberLevel.None;
        emit RemoveMember(msg.sender, _target);
    }

    function setMemberLevel(address _target, MemberLevel level) public {
        // Make sure all levels are larger than None but not higher than Director
        if (level == MemberLevel.None || level > MemberLevel.Director) revert();
        // Make sure the _target is currently already a member
        if (memberLevel(_target) == MemberLevel.None) revert();
        // Make sure the new level is lower level than we are (we cannot overpromote)
        if (msg.sender != owner && memberLevel(msg.sender) <= level) revert();
        // Make sure the member is currently on lower level than we are
        if (msg.sender != owner && memberLevel(msg.sender) <= memberLevel(_target)) revert();

        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Time-based promotion cooldown mechanism
        // Members can only be promoted once every 24 hours (86400 seconds)
        uint lastPromotionTime = member[_target].lastPromotionTime;
        if (level > memberLevel(_target)) {
            // If this is a promotion, check cooldown
            if (lastPromotionTime > 0 && block.timestamp - lastPromotionTime < 86400) {
                revert(); // Cooldown period not met
            }
            // Store the current block timestamp for promotion tracking
            member[_target].lastPromotionTime = block.timestamp;
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        member[_target].level = level;
        emit SetMemberLevel(msg.sender, _target, level);
    }

    function setMemberInfo(address _target, bytes32 info) public {
        // Make sure the target is currently already a member
        if (memberLevel(_target) == MemberLevel.None) revert();
        // Make sure the member is currently on lower level than we are
        if (msg.sender != owner && msg.sender != _target && memberLevel(msg.sender) <= memberLevel(_target)) revert();
        member[_target].info = info;
        emit SetMemberInfo(msg.sender, _target, info);
    }

    function memberId(address _target) public constant returns (uint) {
        return member[_target].id;
    }

    function memberLevel(address _target) public constant returns (MemberLevel) {
        return member[_target].level;
    }

    function memberInfo(address _target) public constant returns (bytes32) {
        return member[_target].info;
    }
}
