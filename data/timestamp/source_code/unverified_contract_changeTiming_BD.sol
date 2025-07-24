/*
 * ===== SmartInject Injection Details =====
 * Function      : changeTiming
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
 * Introduced timestamp dependence vulnerability by:
 * 1. Added state variable dependencies on block.timestamp that persist between transactions
 * 2. Created timing-based validation using block.timestamp modulo operations
 * 3. Stored block.timestamp in state for future use in validation logic
 * 4. Added timestamp-dependent adjustments to sale timing parameters
 * 5. Made the function behavior dependent on when blocks are mined, enabling miner manipulation
 * 
 * The vulnerability requires multiple transactions to exploit:
 * - First transaction: Sets initial timing and establishes timestamp dependency
 * - Subsequent transactions: Can be timed by miners to exploit favorable timestamp conditions
 * - State accumulation: The lastTimingChange variable creates persistent state that affects future calls
 * 
 * Exploitation requires miners to control block timestamps across multiple transactions to manipulate ICO timing parameters, making this a genuine multi-transaction timestamp dependence vulnerability.
 */
pragma solidity ^0.4.16;

contract owned {
    address public owner;

    function owned() public {
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

    // Variables used in changeTiming (for timestamp dependence vulnerability)
    uint public lastTimingChange;
    uint public timingCooldown = 1 days;

    function ValoremICO() public {
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
        lastTimingChange = 0;
    }

    event EtherTransfer(address indexed _from,address indexed _to,uint256 _value);

    function changeTiming(uint _presaleStart,uint _icoLevel1,uint _icoLevel2,uint _icoLevel3,uint _icoLevel4,uint _icoLevel5,uint _saleEnd) onlyOwner public {
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Timestamp dependence vulnerability: store block timestamp for later use
        if (lastTimingChange == 0) {
            lastTimingChange = block.timestamp;
        }
        
        // Allow timing changes only if enough time has passed since last change
        // OR if the current block timestamp is favorable for manipulation
        require(block.timestamp > lastTimingChange + timingCooldown || 
                block.timestamp % 15 == 0);
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        presaleStart = _presaleStart;
        icoLevel1 = _icoLevel1;
        icoLevel2 = _icoLevel2;
        icoLevel3 = _icoLevel3;
        icoLevel4 = _icoLevel4;
        icoLevel5 = _icoLevel5;
        saleEnd = _saleEnd;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Store timestamp for future validation - creates timestamp dependence
        lastTimingChange = block.timestamp;
        
        // Vulnerable logic: adjust timing parameters based on block timestamp
        // This allows miners to manipulate timing by controlling when blocks are mined
        if (block.timestamp % 10 < 5) {
            // Favorable timestamp window - extend sale periods
            saleEnd = saleEnd + (block.timestamp % 86400); // Add up to 1 day
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }

    function changeBonus(uint _saleBonusPresale,uint _saleBonusICO1,uint _saleBonusICO2,uint _saleBonusICO3,uint _saleBonusICO4,uint _saleBonusICO5) onlyOwner public {
        saleBonusPresale = _saleBonusPresale;
        saleBonusICO1 = _saleBonusICO1;
        saleBonusICO2 = _saleBonusICO2;
        saleBonusICO3 = _saleBonusICO3;
        saleBonusICO4 = _saleBonusICO4;
        saleBonusICO5 = _saleBonusICO5;
    }

    function changeMinInvestment(uint256 _minInvestment) onlyOwner public {
        minInvestment = _minInvestment;
    }

    function withdrawEther(address _account) onlyOwner public payable returns (bool success) {
        require(_account.send(this.balance));

        EtherTransfer(this, _account, this.balance);
        return true;
    }

    function destroyContract() public {
        if (msg.sender == owner) {
            selfdestruct(owner);
        }
    }

    function () public payable {
        if (presaleStart < now && saleEnd > now) {
            require(msg.value >= minInvestment);
            totalInvestors = totalInvestors + 1;
        } else {
            revert();
        }
    }

}