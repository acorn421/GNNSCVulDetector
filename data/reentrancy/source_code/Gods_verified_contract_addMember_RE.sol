/*
 * ===== SmartInject Injection Details =====
 * Function      : addMember
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a STATEFUL, MULTI-TRANSACTION reentrancy vulnerability by:
 * 
 * 1. **Moved Critical State Update**: Moved the `memberId[member] = id` assignment to AFTER the external call in the new member branch, creating a window where state is inconsistent.
 * 
 * 2. **Added External Calls**: Introduced realistic external calls to notify the member address about their registration/update using `member.call()` with callback function signatures.
 * 
 * 3. **Created State Inconsistency Window**: During the external call, the member exists in the `members` array but `memberId[member]` is still 0, creating an exploitable state inconsistency.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1**: Attacker calls `addMember()` with a malicious contract address as the member
 * - Member struct is created and added to `members` array with ID (e.g., ID = 5)
 * - External call is made to attacker's contract via `member.call()`
 * - **Critical**: `memberId[member]` is still 0 at this point
 * - Attacker's contract receives the callback and can now call `addMember()` again
 * 
 * **Transaction 2** (Reentrancy during callback): Attacker's contract calls `addMember()` again
 * - Since `memberId[member]` is still 0, the condition `if (memberId[member] == 0)` is true
 * - A NEW member struct is created with a different ID (e.g., ID = 6)
 * - This creates duplicate member entries for the same address
 * - The external call is made again, potentially allowing further reentrancy
 * 
 * **Transaction 3** (Exploitation): Attacker leverages the duplicate member state
 * - Multiple member IDs now exist for the same address
 * - The attacker can exploit functions that rely on member counts or ID consistency
 * - State corruption allows bypassing access controls or manipulating member-based logic
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Accumulation**: The vulnerability depends on the persistent state changes (member array growth) that accumulate across transactions
 * 2. **Reentrancy Window**: The external call creates a window where state is temporarily inconsistent, but only exploitable if the attacker can make additional calls during this window
 * 3. **Persistent Corruption**: The resulting state corruption (duplicate members, inconsistent memberId mapping) persists beyond the initial transaction and can be exploited in subsequent transactions
 */
pragma solidity ^0.4.2;

/* Родительский контракт */
contract Owned {
    /* Адрес владельца контракта*/
    address owner;

    /* Конструктор контракта, вызывается при первом запуске */
    function Owned() public {
        owner = msg.sender;
    }

    /* Изменить владельца контракта, newOwner - адрес нового владельца */
    function changeOwner(address newOwner) onlyowner public {
        owner = newOwner;
    }

    /* Модификатор для ограничения доступа к функциям только для владельца */
    modifier onlyowner() {
        if (msg.sender==owner) _;
    }

    /* Удалить контракт */
    function kill() onlyowner public {
        if (msg.sender == owner) suicide(owner);
    }
}

/* Основной контракт, наследует контракт Owned */
contract Gods is Owned {
    /* Структура представляющая участника */
    struct Member {
        address member;
        string name;
        string surname;
        string patronymic;
        uint birthDate;
        string birthPlace;
        string avatarHash;
        uint avatarID;
        bool approved;
        uint memberSince;
    }

    /* Массив участников */
    Member[] public members;

    /* Маппинг адрес участника -> id участника */
    mapping (address => uint) public memberId;

    /* Маппинг id участника -> приватный ключ кошелька */
    mapping (uint => string) public pks;

    /* Маппинг id участника -> дополнительные данные на участника в формате JSON */
    mapping (uint => string) public memberData;

    /* Событие при добавлении участника, параметры - адрес, ID */
    event MemberAdded(address member, uint id);

    /* Событие при изменении участника, параметры - адрес, ID */
    event MemberChanged(address member, uint id);

    /* Конструктор контракта, вызывается при первом запуске */
    function Gods() public {
        /* Добавляем пустого участника для инициализации */
        addMember('', '', '', 0, '', '', 0, '');
    }

    /* функция добавления и обновления участника, параметры - адрес, имя, фамилия,
     отчество, дата рождения (linux time), место рождения, хэш аватара, ID аватара
     если пользователь с таким адресом не найден, то будет создан новый, в конце вызовется событие
     MemberAdded, если пользователь найден, то будет произведено обновление полей и проставлен флаг
     подтверждения approved */
    function addMember(string name,
        string surname,
        string patronymic,
        uint birthDate,
        string birthPlace,
        string avatarHash,
        uint avatarID,
        string data) onlyowner public {
        uint id;
        address member = msg.sender;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if (memberId[member] == 0) {
            id = members.length++;
            members[id] = Member({
                member: member,
                name: name,
                surname: surname,
                patronymic: patronymic,
                birthDate: birthDate,
                birthPlace: birthPlace,
                avatarHash: avatarHash,
                avatarID: avatarID,
                approved: (owner == member),
                memberSince: now
            });
            memberData[id] = data;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // External notification to member verification service
            // This introduces a reentrancy vulnerability
            if (member != 0) {
                member.call(bytes4(keccak256("onMemberAdded(uint256,string)")), id, data);
                MemberAdded(member, id);
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // State update happens AFTER external call - vulnerable to reentrancy
            memberId[member] = id;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        } else {
            id = memberId[member];
            Member storage m = members[id];
            m.approved = true;
            m.name = name;
            m.surname = surname;
            m.patronymic = patronymic;
            m.birthDate = birthDate;
            m.birthPlace = birthPlace;
            m.avatarHash = avatarHash;
            m.avatarID = avatarID;
            memberData[id] = data;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // External notification about member update
            member.call(bytes4(keccak256("onMemberUpdated(uint256,string)")), id, data);
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            MemberChanged(member, id);
        }
    }
}