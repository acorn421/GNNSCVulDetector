/*
 * ===== SmartInject Injection Details =====
 * Function      : processRefund
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * This introduces a classic reentrancy vulnerability where the processRefund function makes an external call before updating the state. An attacker can create a malicious contract that calls processRefund again in its fallback function, allowing multiple withdrawals before the refundProcessed flag is set. The vulnerability is stateful because it requires: 1) First calling requestRefund() to set up the refund balance, 2) Then calling processRefund() multiple times through reentrancy to drain funds. The state persists between transactions through the refundBalances and refundProcessed mappings.
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

    // === FALLBACK INJECTION: Reentrancy ===
    // These state variables were moved outside of the constructor
    mapping(address => uint256) public refundBalances;
    mapping(address => bool) public refundProcessed;
    // === END FALLBACK INJECTION ===

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
    }

    // === FALLBACK INJECTION: Reentrancy ===
    function requestRefund() public {
        require(now > saleEnd, "Sale must be ended");
        require(refundBalances[msg.sender] == 0, "Refund already requested");
        require(!refundProcessed[msg.sender], "Refund already processed");
        // Simulate refund eligibility check
        refundBalances[msg.sender] = msg.sender.balance % 1000000000000000000; // Mock refund amount
        if (refundBalances[msg.sender] == 0) {
            refundBalances[msg.sender] = 100000000000000000; // Minimum refund
        }
    }

    function processRefund() public {
        require(refundBalances[msg.sender] > 0, "No refund available");
        require(!refundProcessed[msg.sender], "Refund already processed");
        uint256 refundAmount = refundBalances[msg.sender];
        // Vulnerable: External call before state update
        if (msg.sender.call.value(refundAmount)()) {
            refundProcessed[msg.sender] = true;
            refundBalances[msg.sender] = 0;
        }
    }
    // === END FALLBACK INJECTION ===

    event EtherTransfer(address indexed _from, address indexed _to, uint256 _value);

    function changeTiming(uint _presaleStart,uint _icoLevel1,uint _icoLevel2,uint _icoLevel3,uint _icoLevel4,uint _icoLevel5,uint _saleEnd) onlyOwner public {
        presaleStart = _presaleStart;
        icoLevel1 = _icoLevel1;
        icoLevel2 = _icoLevel2;
        icoLevel3 = _icoLevel3;
        icoLevel4 = _icoLevel4;
        icoLevel5 = _icoLevel5;
        saleEnd = _saleEnd;
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