/*
 * ===== SmartInject Injection Details =====
 * Function      : insertCharacter
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **State Inconsistency Window**: Added an external call between pushing to the characters array and incrementing characterNo, creating a window where state is inconsistent
 * 
 * 2. **Multi-Transaction Exploitation Path**: 
 *    - Transaction 1: Attacker calls insertCharacter with crafted name, triggers external call
 *    - External call re-enters insertCharacter multiple times before characterNo is incremented
 *    - Each re-entry sees the same characterNo but characters array grows
 *    - Transaction 2+: Attacker can exploit the ID/array length mismatch
 * 
 * 3. **Stateful Vulnerability**: The vulnerability requires:
 *    - Previous insertCharacter calls to establish characters in the array
 *    - Multiple transactions to accumulate the state inconsistency
 *    - The gap between characters.push() and characterNo++ enables exploitation
 * 
 * 4. **Realistic Integration**: Added observer pattern callback that would be natural in a gaming system for character creation notifications
 * 
 * 5. **Exploitation Scenario**: 
 *    - Attacker can create multiple characters with the same expected ID
 *    - Characters array length becomes misaligned with characterNo
 *    - Subsequent calls to getCharacterDetails or other functions may access wrong character data
 *    - The vulnerability compounds over multiple transactions as the mismatch grows
 * 
 * The vulnerability is only exploitable through multiple transactions because the external call must be made to a contract that re-enters, and the state corruption accumulates over time rather than being exploitable in a single atomic transaction.
 */
pragma solidity ^0.4.19;
/*
Name: Genesis
Dev: White Matrix co,. Ltd
*/

library SafeMath {

    /**
    * @dev Multiplies two numbers, throws on overflow.
    */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }
        uint256 c = a * b;
        assert(c / a == b);
        return c;
    }

    /**
    * @dev Integer division of two numbers, truncating the quotient.
    */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        // assert(b > 0); // Solidity automatically throws when dividing by 0
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold
        return c;
    }

    /**
    * @dev Substracts two numbers, throws on overflow (i.e. if subtrahend is greater than minuend).
    */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b <= a);
        return a - b;
    }

    /**
    * @dev Adds two numbers, throws on overflow.
    */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }
}

contract Genesis {
    using SafeMath for uint256;

    //mutabilityType
    //Genesis parameter
    uint public characterNo = 3;
    uint public version = 1;

    struct Character {
        string name;
        uint hp;
        uint mp;
        uint str;
        uint intelli;
        uint san;
        uint luck;
        uint charm;
        uint mt;
        string optionalAttrs;
    }

    Character[] characters;

    function Genesis() public {
        characters.push(Character("Adam0", 100, 100, 50, 50, 50, 50, 50, 0, ""));
        characters.push(Character("Adam1", 100, 100, 50, 50, 50, 50, 50, 1, ""));
        characters.push(Character("Adam2", 100, 100, 50, 50, 50, 50, 50, 2, ""));
    }

    function getCharacterNo() view returns (uint _characterNo){
        return characterNo;
    }

    function setCharacterAttributes(uint _id, uint _hp, uint _mp, uint _str, uint _intelli, uint _san, uint _luck, uint _charm, string _optionalAttrs){
        //require check
        require(characters[_id].mt == 2);
        //read directly from mem
        Character affectedCharacter = characters[_id];

        affectedCharacter.hp = _hp;
        affectedCharacter.mp = _mp;
        affectedCharacter.str = _str;
        affectedCharacter.intelli = _intelli;
        affectedCharacter.san = _san;
        affectedCharacter.luck = _luck;
        affectedCharacter.charm = _charm;
        affectedCharacter.optionalAttrs = _optionalAttrs;

        //need rewrite as a function
        if (affectedCharacter.hp < 0) {
            affectedCharacter.hp = 0;
        } else if (affectedCharacter.hp > 100) {
            affectedCharacter.hp = 100;

        } else if (affectedCharacter.mp < 0) {
            affectedCharacter.mp = 0;

        } else if (affectedCharacter.mp > 100) {
            affectedCharacter.mp = 100;

        } else if (affectedCharacter.str < 0) {
            affectedCharacter.str = 0;

        } else if (affectedCharacter.str > 100) {
            affectedCharacter.str = 100;

        } else if (affectedCharacter.intelli < 0) {
            affectedCharacter.intelli = 0;

        } else if (affectedCharacter.intelli > 100) {
            affectedCharacter.intelli = 100;

        } else if (affectedCharacter.san < 0) {
            affectedCharacter.san = 0;

        } else if (affectedCharacter.san > 100) {
            affectedCharacter.san = 100;

        } else if (affectedCharacter.luck < 0) {
            affectedCharacter.luck = 0;

        } else if (affectedCharacter.luck > 100) {
            affectedCharacter.luck = 100;

        } else if (affectedCharacter.charm < 0) {
            affectedCharacter.charm = 0;

        } else if (affectedCharacter.charm > 100) {
            affectedCharacter.charm = 100;
        }

        characters[_id] = affectedCharacter;
    }

    function affectCharacter(uint _id, uint isPositiveEffect){
        require(characters[_id].mt != 0);
        Character affectedCharacter = characters[_id];
        if (isPositiveEffect == 0) {
            affectedCharacter.hp = affectedCharacter.hp - getRand();
            affectedCharacter.mp = affectedCharacter.mp - getRand();
            affectedCharacter.str = affectedCharacter.str - getRand();
            affectedCharacter.intelli = affectedCharacter.intelli - getRand();
            affectedCharacter.san = affectedCharacter.san - getRand();
            affectedCharacter.luck = affectedCharacter.luck - getRand();
            affectedCharacter.charm = affectedCharacter.charm - getRand();
        } else if (isPositiveEffect == 1) {
            affectedCharacter.hp = affectedCharacter.hp + getRand();
            affectedCharacter.mp = affectedCharacter.mp + getRand();
            affectedCharacter.str = affectedCharacter.str + getRand();
            affectedCharacter.intelli = affectedCharacter.intelli + getRand();
            affectedCharacter.san = affectedCharacter.san + getRand();
            affectedCharacter.luck = affectedCharacter.luck + getRand();
            affectedCharacter.charm = affectedCharacter.charm + getRand();
        }
        //need rewrite as a function
        if (affectedCharacter.hp < 0) {
            affectedCharacter.hp = 0;
        } else if (affectedCharacter.hp > 100) {
            affectedCharacter.hp = 100;

        } else if (affectedCharacter.mp < 0) {
            affectedCharacter.mp = 0;

        } else if (affectedCharacter.mp > 100) {
            affectedCharacter.mp = 100;

        } else if (affectedCharacter.str < 0) {
            affectedCharacter.str = 0;

        } else if (affectedCharacter.str > 100) {
            affectedCharacter.str = 100;

        } else if (affectedCharacter.intelli < 0) {
            affectedCharacter.intelli = 0;

        } else if (affectedCharacter.intelli > 100) {
            affectedCharacter.intelli = 100;

        } else if (affectedCharacter.san < 0) {
            affectedCharacter.san = 0;

        } else if (affectedCharacter.san > 100) {
            affectedCharacter.san = 100;

        } else if (affectedCharacter.luck < 0) {
            affectedCharacter.luck = 0;

        } else if (affectedCharacter.luck > 100) {
            affectedCharacter.luck = 100;

        } else if (affectedCharacter.charm < 0) {
            affectedCharacter.charm = 0;

        } else if (affectedCharacter.charm > 100) {
            affectedCharacter.charm = 100;
        }

        characters[_id] = affectedCharacter;
    }


    function getRand() public view returns (uint256 _rand){
        uint256 rand = uint256(sha256(block.timestamp, block.number - uint256(0) - 1)) % 10 + 1;
        return rand;
    }

    function insertCharacter(string _name, uint _hp, uint _mp, uint _str, uint _intelli, uint _san, uint _luck, uint _charm, uint _mt, string _optionalAttrs) returns (uint){
        require(checkLegal(_hp, _mp, _str, _intelli, _san, _luck, _charm, _mt) == 1);
        //需要check合法性
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Store the character ID that will be assigned
        uint newCharacterId = characterNo;
        
        // Create character first (state change)
        characters.push(Character(_name, _hp, _mp, _str, _intelli, _san, _luck, _charm, _mt, _optionalAttrs));
        
        // External call to notify observer before updating characterNo
        // This allows reentrancy where characterNo is inconsistent with characters array length
        if (bytes(_name).length > 0) {
            // Call external observer/callback contract if name is provided
            address observerContract = address(bytes20(keccak256(_name)) >> 96);
            if (observerContract.call(bytes4(keccak256("onCharacterCreated(uint256,string)")), newCharacterId, _name)) {
                // External call succeeded, continue
            }
        }
        
        // Update characterNo after external call (vulnerable to reentrancy)
        characterNo++;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return characterNo;
    }

    function checkLegal(uint _hp, uint _mp, uint _str, uint _intelli, uint _san, uint _luck, uint _charm, uint _mt) returns (uint _checkresult){
        if ((_hp < 0) || (_hp > 9999)) {
            return 0;
        } else if ((_mp < 0) || (_mp > 9999)) {
            return 0;
        } else if ((_str < 0) || (_str > 9999)) {
            return 0;
        } else if ((_intelli < 0) || (_intelli > 9999)) {
            return 0;
        } else if ((_san < 0) || (_san > 9999)) {
            return 0;
        } else if ((_luck < 0) || (_luck > 9999)) {
            return 0;
        } else if ((_charm < 0) || (_charm > 9999)) {
            return 0;
        } else if ((_mt < 0) || (_mt > 2)) {
            return 0;
        }
        return 1;
    }

    // This function will return all of the details of the characters
    function getCharacterDetails(uint _characterId) public view returns (
        string _name,
        uint _hp,
        uint _mp,
        uint _str,
        uint _int,
        uint _san,
        uint _luck,
        uint _charm,
        uint _mt,
        string _optionalAttrs
    ) {

        Character storage _characterInfo = characters[_characterId];

        _name = _characterInfo.name;
        _hp = _characterInfo.hp;
        _mp = _characterInfo.mp;
        _str = _characterInfo.str;
        _int = _characterInfo.intelli;
        _san = _characterInfo.san;
        _luck = _characterInfo.luck;
        _charm = _characterInfo.charm;
        _mt = _characterInfo.mt;
        _optionalAttrs = _characterInfo.optionalAttrs;
    }
}
