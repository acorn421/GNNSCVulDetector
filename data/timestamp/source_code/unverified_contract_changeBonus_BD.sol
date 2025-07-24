/*
 * ===== SmartInject Injection Details =====
 * Function      : changeBonus
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability where:
 * 
 * 1. **Specific Changes Made:**
 *    - Added time-based bonus calculations using `block.timestamp`
 *    - Created predictable decay patterns based on day-rounded timestamps
 *    - Bonuses are modified by a `decayFactor` calculated from current timestamp
 *    - Added `lastChangeTime` state variable to track when changes occur
 * 
 * 2. **Multi-Transaction Exploitation Process:**
 *    - **Transaction 1 (Setup)**: Attacker observes when owner calls `changeBonus` and notes the timestamp patterns
 *    - **Transaction 2 (Timing)**: Attacker waits for specific timestamp conditions (e.g., specific day boundary)
 *    - **Transaction 3 (Exploitation)**: Attacker triggers ICO participation through the fallback function when bonuses are artificially inflated due to predictable timestamp calculations
 * 
 * 3. **Why Multi-Transaction Required:**
 *    - The vulnerability depends on the timestamp when `changeBonus` is called, creating persistent state
 *    - Exploitation requires waiting for specific timestamp conditions to maximize bonus values
 *    - The attacker must first observe the pattern, then time their investment to coincide with favorable timestamp-based bonus calculations
 *    - The bonus values persist in state between transactions, allowing the attacker to benefit from the predictable time-based modifications in subsequent ICO participation
 * 
 * 4. **Exploitation Scenario:**
 *    - Owner calls `changeBonus` at timestamp T1
 *    - Attacker calculates that calling at timestamp T2 (next day boundary) will result in higher bonuses
 *    - Attacker participates in ICO at T2 when bonuses are artificially inflated due to predictable timestamp arithmetic
 *    - The vulnerability is stateful (bonus values persist) and requires multiple transactions (setup observation, timing calculation, exploitation)
 */
pragma solidity ^0.4.16;

contract owned {
    address public owner;

    function owned() {
        owner = msg.sender;
    }

    modifier onlyOwner {
        if (msg.sender != owner) {
            revert();
        }
        _;
    }
}

library SafeMath {
	function mul(uint256 a, uint256 b) internal constant returns (uint256) {
		uint256 c = a * b;
		assert(a == 0 || c / a == b);
		return c;
	}

	function div(uint256 a, uint256 b) internal constant returns (uint256) {
		uint256 c = a / b;
		return c;
	}

	function sub(uint256 a, uint256 b) internal constant returns (uint256) {
		assert(b <= a);
		return a - b;
	}

	function add(uint256 a, uint256 b) internal constant returns (uint256) {
		uint256 c = a + b;
		assert(c >= a);
		return c;
	}
}

contract ValoremICO is owned {

    // Timeline
    uint public presaleStart;
    uint public icoLevel1;
    uint public icoLevel2;
    uint public icoLevel3;
    uint public icoLevel4;
    uint public icoLevel5;
    uint public saleEnd;

    // Bonus Values
    uint256 public saleBonusPresale;
    uint256 public saleBonusICO1;
    uint256 public saleBonusICO2;
    uint256 public saleBonusICO3;
    uint256 public saleBonusICO4;
    uint256 public saleBonusICO5;
    uint256 public totalInvestors;

    // Min Investment
    uint256 public minInvestment;

    function ValoremICO() {
        presaleStart = 1513036800;
        icoLevel1 = 1517097600;
        icoLevel2 = 1519776000;
        icoLevel3 = 1522195200;
        icoLevel4 = 1524873600;
        icoLevel5 = 1527465600;
        saleEnd = 1530144000;

        saleBonusPresale = 100;
        saleBonusICO1 = 50;
        saleBonusICO2 = 40;
        saleBonusICO3 = 20;
        saleBonusICO4 = 10;
        saleBonusICO5 = 5;

        minInvestment = (1/10) * (10 ** 18);
    }

    event EtherTransfer(address indexed _from,address indexed _to,uint256 _value);

    function changeTiming(uint _presaleStart,uint _icoLevel1,uint _icoLevel2,uint _icoLevel3,uint _icoLevel4,uint _icoLevel5,uint _saleEnd) onlyOwner {
        presaleStart = _presaleStart;
        icoLevel1 = _icoLevel1;
        icoLevel2 = _icoLevel2;
        icoLevel3 = _icoLevel3;
        icoLevel4 = _icoLevel4;
        icoLevel5 = _icoLevel5;
        saleEnd = _saleEnd;
    }

    function changeBonus(uint _saleBonusPresale,uint _saleBonusICO1,uint _saleBonusICO2,uint _saleBonusICO3,uint _saleBonusICO4,uint _saleBonusICO5) onlyOwner {
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Store the timestamp when bonus changes are requested
        uint lastChangeTime = block.timestamp;
        
        // Time-based bonus decay: bonuses automatically reduce over time
        // This creates a predictable pattern that can be exploited
        uint timeSinceLastChange = lastChangeTime - (lastChangeTime % 86400); // Round to day
        uint decayFactor = (timeSinceLastChange / 86400) % 10; // 0-9 based on day
        
        // Apply time-based modifications that can be predicted and exploited
        saleBonusPresale = _saleBonusPresale + (decayFactor * 5);
        saleBonusICO1 = _saleBonusICO1 + (decayFactor * 3);
        saleBonusICO2 = _saleBonusICO2 + (decayFactor * 2);
        saleBonusICO3 = _saleBonusICO3 + decayFactor;
        saleBonusICO4 = _saleBonusICO4 + decayFactor;
        saleBonusICO5 = _saleBonusICO5 + decayFactor;
        
        // Store the change timestamp for future reference
        // This creates state that persists and affects future transactions
        lastChangeTime = block.timestamp;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }

    function changeMinInvestment(uint256 _minInvestment) onlyOwner {
        minInvestment = _minInvestment;
    }

    function withdrawEther(address _account) onlyOwner payable returns (bool success) {
        require(_account.send(this.balance));

        EtherTransfer(this, _account, this.balance);
        return true;
    }

    function destroyContract() {
        if (msg.sender == owner) {
            selfdestruct(owner);
        }
    }

    function () payable {
        if (presaleStart < now && saleEnd > now) {
            require(msg.value >= minInvestment);
            totalInvestors = totalInvestors + 1;
        } else {
            revert();
        }
    }

}