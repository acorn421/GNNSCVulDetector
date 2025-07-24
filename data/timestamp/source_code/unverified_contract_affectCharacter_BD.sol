/*
 * ===== SmartInject Injection Details =====
 * Function      : affectCharacter
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through time-based effect multipliers. The vulnerability manifests in several ways:
 * 
 * **Specific Changes Made:**
 * 1. **Added timestamp-dependent state variables**: `lastEffectTime`, `effectStreak`, and `timeBasedMultiplier` mappings that persist between transactions
 * 2. **Implemented time-based multiplier logic**: Uses `block.timestamp` to calculate effect multipliers based on time intervals between function calls
 * 3. **Created streak accumulation mechanism**: Rapid consecutive calls within 60 seconds build up `effectStreak` values
 * 4. **Added vulnerable timestamp calculations**: Uses `block.timestamp % 10` and `block.timestamp % 5` for critical multiplier calculations
 * 
 * **Multi-Transaction Exploitation Mechanism:**
 * 1. **Transaction 1**: Attacker calls the function to establish initial timestamp (`lastEffectTime[_id]`)
 * 2. **Transaction 2+**: Attacker makes rapid successive calls within 60-second windows to accumulate `effectStreak` values
 * 3. **Exploitation**: Each call within the time window increases the multiplier, amplifying character stat changes significantly
 * 4. **Miner Manipulation**: Malicious miners can manipulate `block.timestamp` to:
 *    - Ensure calls fall within favorable time windows
 *    - Manipulate the `block.timestamp % 10` calculation to achieve maximum multipliers
 *    - Reset or extend streak timers artificially
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability requires establishing a baseline timestamp in the first transaction
 * - Subsequent transactions build upon the stored state (`effectStreak`, `timeBasedMultiplier`)
 * - The exploit becomes more powerful with each successive transaction within the time window
 * - Single-transaction exploitation is impossible because the multiplier logic depends on comparing current time with previously stored timestamps
 * 
 * **Attack Scenarios:**
 * - **Rapid-Fire Boost**: Multiple quick transactions within 60 seconds create exponentially increasing multipliers
 * - **Timing Manipulation**: Miners can adjust timestamps to maximize `block.timestamp % 10` values
 * - **Streak Exploitation**: Attackers can maintain long streaks by precisely timing their transactions
 * - **Coordinated Attacks**: Multiple attackers could coordinate to exploit specific timestamp patterns
 * 
 * This creates a realistic timestamp dependence vulnerability that requires careful timing across multiple transactions to fully exploit.
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

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping(uint => uint) public lastEffectTime;
    mapping(uint => uint) public effectStreak;
    mapping(uint => uint) public timeBasedMultiplier;
    
    function affectCharacter(uint _id, uint isPositiveEffect){
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        require(characters[_id].mt != 0);
        Character affectedCharacter = characters[_id];
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Timestamp-dependent logic for effect multipliers
        uint currentTime = block.timestamp;
        uint timeSinceLastEffect = currentTime - lastEffectTime[_id];
        
        // Critical vulnerability: Time-based multiplier accumulation
        if (timeSinceLastEffect < 60) { // Less than 1 minute
            effectStreak[_id] = effectStreak[_id] + 1;
            // Vulnerable: Uses block.timestamp for critical multiplier calculation
            timeBasedMultiplier[_id] = (block.timestamp % 10) + effectStreak[_id];
        } else if (timeSinceLastEffect < 300) { // Less than 5 minutes
            timeBasedMultiplier[_id] = (block.timestamp % 5) + 1;
        } else {
            effectStreak[_id] = 0;
            timeBasedMultiplier[_id] = 1;
        }
        
        // Store timestamp for next call comparison
        lastEffectTime[_id] = currentTime;
        
        uint multiplier = timeBasedMultiplier[_id];
        
        if (isPositiveEffect == 0) {
            affectedCharacter.hp = affectedCharacter.hp - (getRand() * multiplier);
            affectedCharacter.mp = affectedCharacter.mp - (getRand() * multiplier);
            affectedCharacter.str = affectedCharacter.str - (getRand() * multiplier);
            affectedCharacter.intelli = affectedCharacter.intelli - (getRand() * multiplier);
            affectedCharacter.san = affectedCharacter.san - (getRand() * multiplier);
            affectedCharacter.luck = affectedCharacter.luck - (getRand() * multiplier);
            affectedCharacter.charm = affectedCharacter.charm - (getRand() * multiplier);
        } else if (isPositiveEffect == 1) {
            affectedCharacter.hp = affectedCharacter.hp + (getRand() * multiplier);
            affectedCharacter.mp = affectedCharacter.mp + (getRand() * multiplier);
            affectedCharacter.str = affectedCharacter.str + (getRand() * multiplier);
            affectedCharacter.intelli = affectedCharacter.intelli + (getRand() * multiplier);
            affectedCharacter.san = affectedCharacter.san + (getRand() * multiplier);
            affectedCharacter.luck = affectedCharacter.luck + (getRand() * multiplier);
            affectedCharacter.charm = affectedCharacter.charm + (getRand() * multiplier);
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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