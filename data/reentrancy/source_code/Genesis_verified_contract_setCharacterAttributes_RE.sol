/*
 * ===== SmartInject Injection Details =====
 * Function      : setCharacterAttributes
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a user-controlled contract address (derived from _optionalAttrs parameter) when the character's total power exceeds 400. The vulnerability requires: 1) First transaction to set character attributes below the 400 threshold, 2) Second transaction to increase attributes above 400 threshold, triggering the external call that can reenter the function before state validation occurs. The external call happens after temporary state updates but before final validation and storage, creating a window for reentrancy exploitation where the attacker can manipulate character state during the callback.
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
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

        // Check if character has accumulated enough power (state dependency)
        uint totalPower = affectedCharacter.hp + affectedCharacter.mp + affectedCharacter.str + affectedCharacter.intelli + affectedCharacter.san + affectedCharacter.luck + affectedCharacter.charm;
        
        // External call to notify enhancement system before state validation
        // This creates a reentrancy opportunity when total power exceeds threshold
        if (totalPower > 400) {
            // Call external enhancement validator - vulnerable to reentrancy
            bytes memory callData = abi.encodeWithSignature("onPowerThresholdReached(uint256,uint256)", _id, totalPower);
            bool success = address(uint160(uint256(keccak256(abi.encodePacked(_optionalAttrs))))).call(callData);
            if (!success) {
                // Continue execution even if external call fails
            }
        }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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
        uint256 rand = uint256(sha256(block.timestamp, block.number - rand - 1)) % 10 + 1;
        return rand;
    }

    function insertCharacter(string _name, uint _hp, uint _mp, uint _str, uint _intelli, uint _san, uint _luck, uint _charm, uint _mt, string _optionalAttrs) returns (uint){
        require(checkLegal(_hp, _mp, _str, _intelli, _san, _luck, _charm, _mt) == 1);
        //需要check合法性
        characterNo++;
        characters.push(Character(_name, _hp, _mp, _str, _intelli, _san, _luck, _charm, _mt, _optionalAttrs));

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