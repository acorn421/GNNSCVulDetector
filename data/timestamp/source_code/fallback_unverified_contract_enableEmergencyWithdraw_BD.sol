/*
 * ===== SmartInject Injection Details =====
 * Function      : enableEmergencyWithdraw
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
 * This vulnerability introduces a multi-transaction timestamp dependence issue. The emergency withdrawal system requires three separate transactions over time: 1) Request emergency withdrawal, 2) Enable emergency withdrawal after delay, 3) Execute withdrawal. The vulnerability lies in the reliance on 'now' (block.timestamp) for timing checks, which can be manipulated by miners within a 15-second window. A malicious miner could manipulate timestamps to bypass the intended delay mechanisms, potentially allowing premature emergency withdrawals or manipulation of the withdrawal timing sequence.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // Emergency withdrawal system - vulnerable to timestamp manipulation
    bool public emergencyWithdrawEnabled = false;
    uint256 public emergencyWithdrawDelay = 86400; // 24 hours in seconds
    uint256 public emergencyWithdrawRequestTime;
    mapping(address => bool) public emergencyWithdrawRequests;
    mapping(address => uint256) public emergencyWithdrawRequestTimestamp;

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

    // Step 1: Request emergency withdrawal (first transaction)
    function requestEmergencyWithdraw() public {
        require(!emergencyWithdrawEnabled, "Emergency withdrawal already enabled");
        require(now >= saleEnd, "Sale must be ended");
        
        emergencyWithdrawRequests[msg.sender] = true;
        emergencyWithdrawRequestTimestamp[msg.sender] = now;
        emergencyWithdrawRequestTime = now;
    }
    
    // Step 2: Enable emergency withdrawal after delay (second transaction)
    function enableEmergencyWithdraw() public onlyOwner {
        require(emergencyWithdrawRequestTime > 0, "No emergency withdrawal request");
        require(now >= emergencyWithdrawRequestTime + emergencyWithdrawDelay, "Emergency withdrawal delay not met");
        
        emergencyWithdrawEnabled = true;
    }
    
    // Step 3: Execute emergency withdrawal (third transaction)
    function executeEmergencyWithdraw() public {
        require(emergencyWithdrawEnabled, "Emergency withdrawal not enabled");
        require(emergencyWithdrawRequests[msg.sender], "No emergency withdrawal request from sender");
        require(now >= emergencyWithdrawRequestTimestamp[msg.sender] + emergencyWithdrawDelay, "Personal withdrawal delay not met");
        
        uint256 amount = this.balance / totalInvestors;
        require(amount > 0, "No funds available");
        
        emergencyWithdrawRequests[msg.sender] = false;
        msg.sender.transfer(amount);
    }
    // === END FALLBACK INJECTION ===

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
        saleBonusPresale = _saleBonusPresale;
        saleBonusICO1 = _saleBonusICO1;
        saleBonusICO2 = _saleBonusICO2;
        saleBonusICO3 = _saleBonusICO3;
        saleBonusICO4 = _saleBonusICO4;
        saleBonusICO5 = _saleBonusICO5;
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
