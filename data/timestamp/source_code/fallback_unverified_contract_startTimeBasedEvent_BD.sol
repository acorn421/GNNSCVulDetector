/*
 * ===== SmartInject Injection Details =====
 * Function      : startTimeBasedEvent
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue where the contract relies on block.timestamp (now) for time-based events. The vulnerability is stateful and multi-transaction: 1) First transaction calls startTimeBasedEvent() to initiate an event with a specific duration, 2) The contract stores the start time and event state, 3) Second transaction calls completeTimeBasedEvent() after the duration has passed. The vulnerability allows miners to manipulate the timestamp in the completion transaction to achieve perfect timing bonuses, getting maximum rewards by setting the timestamp to exactly match the event duration. This requires multiple transactions and persistent state between them.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Time-based event system for character evolution
    mapping(uint => uint) public eventStartTime;
    mapping(uint => bool) public eventActive;
    mapping(uint => uint) public eventDuration;
    
    function startTimeBasedEvent(uint _characterId, uint _durationHours) public {
        require(_characterId < characters.length);
        require(characters[_characterId].mt != 0);
        require(!eventActive[_characterId]);
        
        eventStartTime[_characterId] = now;
        eventActive[_characterId] = true;
        eventDuration[_characterId] = _durationHours * 1 hours;
    }
    
    function completeTimeBasedEvent(uint _characterId) public {
        require(_characterId < characters.length);
        require(eventActive[_characterId]);
        require(now >= eventStartTime[_characterId] + eventDuration[_characterId]);
        
        // Reward based on event completion time - vulnerable to timestamp manipulation
        uint timePassed = now - eventStartTime[_characterId];
        uint bonusMultiplier = 1;
        
        // Miners can manipulate timestamp to get maximum bonus
        if (timePassed == eventDuration[_characterId]) {
            bonusMultiplier = 3; // Perfect timing bonus
        } else if (timePassed <= eventDuration[_characterId] + 300) {
            bonusMultiplier = 2; // Close timing bonus
        }
        
        Character storage character = characters[_characterId];
        character.hp = character.hp + (10 * bonusMultiplier);
        character.mp = character.mp + (10 * bonusMultiplier);
        character.str = character.str + (5 * bonusMultiplier);
        character.intelli = character.intelli + (5 * bonusMultiplier);
        
        // Reset event state
        eventActive[_characterId] = false;
        eventStartTime[_characterId] = 0;
        eventDuration[_characterId] = 0;
    }
    // === END FALLBACK INJECTION ===

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
        Character memory affectedCharacter = characters[_id];

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
        Character memory affectedCharacter = characters[_id];
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
        uint256 rand = uint256(sha256(block.timestamp, block.number - 1)) % 10 + 1;
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