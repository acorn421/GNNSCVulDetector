/*
 * ===== SmartInject Injection Details =====
 * Function      : insertCharacter
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
 * This injection introduces a stateful, multi-transaction timestamp dependence vulnerability through a time-based character creation bonus system. The vulnerability requires multiple transactions because:
 * 
 * 1. **State Accumulation**: The contract tracks `lastCreationTimestamp` and `totalCreationCount` which accumulate across transactions
 * 2. **Time Window Exploitation**: Bonus multipliers are granted based on time elapsed since the last character creation, creating windows that can be exploited
 * 3. **Progressive Unlocking**: Character types (mt values) are unlocked over time periods, requiring the contract to be deployed and aged before exploitation
 * 4. **Timestamp Manipulation**: Miners can manipulate block timestamps to:
 *    - Create characters during bonus windows for enhanced stats
 *    - Bypass time-based restrictions on character types
 *    - Exploit the timing calculation between sequential creations
 * 
 * **Multi-Transaction Exploitation Process**:
 * 1. **Transaction 1**: Create initial character to establish `lastCreationTimestamp`
 * 2. **Wait/Manipulation**: Manipulate block timestamp or wait for bonus window
 * 3. **Transaction 2**: Create character during bonus window to receive multiplied stats
 * 4. **Repeat**: Continue exploiting timing windows for maximum benefit
 * 
 * The vulnerability is realistic because it mimics common game mechanics (time-based bonuses, progressive unlocking) while being exploitable through timestamp manipulation techniques used by miners.
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

    // Genesis parameter
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

    // ====== Added missing state variables used in insertCharacter ======
    uint public lastCreationTimestamp;
    uint public totalCreationCount;
    mapping(uint => uint) public creationTimestamps;
    uint public contractDeployTime = now;
    // ================================================================

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
        if (affectedCharacter.hp > 100) {
            affectedCharacter.hp = 100;
        } else if (affectedCharacter.mp > 100) {
            affectedCharacter.mp = 100;
        } else if (affectedCharacter.str > 100) {
            affectedCharacter.str = 100;
        } else if (affectedCharacter.intelli > 100) {
            affectedCharacter.intelli = 100;
        } else if (affectedCharacter.san > 100) {
            affectedCharacter.san = 100;
        } else if (affectedCharacter.luck > 100) {
            affectedCharacter.luck = 100;
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
        if (affectedCharacter.hp > 100) {
            affectedCharacter.hp = 100;
        } else if (affectedCharacter.mp > 100) {
            affectedCharacter.mp = 100;
        } else if (affectedCharacter.str > 100) {
            affectedCharacter.str = 100;
        } else if (affectedCharacter.intelli > 100) {
            affectedCharacter.intelli = 100;
        } else if (affectedCharacter.san > 100) {
            affectedCharacter.san = 100;
        } else if (affectedCharacter.luck > 100) {
            affectedCharacter.luck = 100;
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based character creation bonus system
        uint creationTime = block.timestamp;
        uint timeSinceLastCreation = creationTime - lastCreationTimestamp;
        
        // Bonus stats for characters created within bonus windows
        uint bonusMultiplier = 1;
        if (timeSinceLastCreation >= 300 && timeSinceLastCreation <= 600) { // 5-10 minute bonus window
            bonusMultiplier = 2;
        } else if (timeSinceLastCreation >= 100 && timeSinceLastCreation <= 200) { // 100-200 second bonus window
            bonusMultiplier = 3;
        }
        
        // Apply time-based bonuses
        _hp = _hp * bonusMultiplier;
        _mp = _mp * bonusMultiplier;
        _str = _str * bonusMultiplier;
        _intelli = _intelli * bonusMultiplier;
        _san = _san * bonusMultiplier;
        _luck = _luck * bonusMultiplier;
        _charm = _charm * bonusMultiplier;
        
        // Progressive unlocking: higher mt values available only after certain time periods
        if (creationTime - contractDeployTime >= 86400) { // 1 day after deployment
            // mt = 2 characters unlocked
        } else if (creationTime - contractDeployTime >= 3600) { // 1 hour after deployment
            // mt = 1 characters unlocked
            require(_mt <= 1);
        } else {
            // Only mt = 0 characters allowed initially
            require(_mt == 0);
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        characterNo++;
        string memory local_name = _name;
        string memory local_optionalAttrs = _optionalAttrs;
        characters.push(Character(local_name, _hp, _mp, _str, _intelli, _san, _luck, _charm, _mt, local_optionalAttrs));
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Update state for next creation
        lastCreationTimestamp = creationTime;
        totalCreationCount++;
        
        // Store creation timestamp in character for future reference
        creationTimestamps[characterNo] = creationTime;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

        return characterNo;
    }

    function checkLegal(uint _hp, uint _mp, uint _str, uint _intelli, uint _san, uint _luck, uint _charm, uint _mt) returns (uint _checkresult){
        if ((_hp > 9999)) {
            return 0;
        } else if ((_mp > 9999)) {
            return 0;
        } else if ((_str > 9999)) {
            return 0;
        } else if ((_intelli > 9999)) {
            return 0;
        } else if ((_san > 9999)) {
            return 0;
        } else if ((_luck > 9999)) {
            return 0;
        } else if ((_charm > 9999)) {
            return 0;
        } else if ((_mt > 2)) {
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
