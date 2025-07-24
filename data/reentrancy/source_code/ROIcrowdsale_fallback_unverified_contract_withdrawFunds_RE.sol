/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawFunds
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This injection introduces a stateful, multi-transaction reentrancy vulnerability through emergency withdrawal functionality. The vulnerability requires: 1) First transaction to record user balances via recordUserBalance(), 2) Second transaction to trigger the reentrancy in emergencyWithdraw() which calls external contract before updating state. The vulnerability is stateful because it depends on the userBalances mapping that persists between transactions and requires multiple calls to exploit.
 */
pragma solidity ^0.4.16;

interface Token {
    function transferFrom(address _from, address _to, uint256 _value) external returns (bool success);
}

contract ROIcrowdsale {
    
    Token public tokenReward;
    address public creator;
    address public owner = 0xc0c026e307B1B74f8d307181Db00CBe2A1B412e0;

    uint256 public price;
    uint256 public tokenSold;

    event FundTransfer(address backer, uint amount, bool isContribution);

    // === FALLBACK INJECTION: Reentrancy ===
    // Moved mapping declaration here, outside the constructor
    mapping(address => uint256) public userBalances;

    constructor() public {
        creator = msg.sender;
        price = 26000;
        tokenReward = Token(0x15DE05E084E4C0805d907fcC2Dc5651023c57A48);
    }

    function emergencyWithdraw(uint256 _amount) public {
        require(userBalances[msg.sender] >= _amount);
        // Vulnerable to reentrancy - external call before state update
        if(msg.sender.call.value(_amount)()) {
            userBalances[msg.sender] -= _amount;
        }
    }

    function recordUserBalance(address _user, uint256 _amount) public {
        require(msg.sender == creator);
        userBalances[_user] += _amount;
    }

    function withdrawFunds(uint256 _amount) public {
        require(userBalances[msg.sender] >= _amount);
        require(_amount > 0);
        // First transaction: reduce balance
        userBalances[msg.sender] -= _amount;
        // Second transaction vulnerability: external call that can reenter
        bool success;
        bytes memory res;
        (success, res) = msg.sender.call.value(_amount)("");
        if (!success) {
            // Revert the balance change if transfer fails
            userBalances[msg.sender] += _amount;
        }
    }
    // === END FALLBACK INJECTION ===

    function setOwner(address _owner) public {
        require(msg.sender == creator);
        owner = _owner;      
    }

    function setCreator(address _creator) public {
        require(msg.sender == creator);
        creator = _creator;      
    }

    function setPrice(uint256 _price) public {
        require(msg.sender == creator);
        price = _price;      
    }
    
    function kill() public {
        require(msg.sender == creator);
        selfdestruct(owner);
    }
    
    function () payable public {
        require(msg.value > 0);
        require(tokenSold < 138216001);
        uint256 _price = price / 10;
        if(tokenSold < 45136000) {
            _price *= 4;
            _price += price; 
        }
        if(tokenSold > 45135999 && tokenSold < 92456000) {
            _price *= 3;
            _price += price;
        }
        if(tokenSold > 92455999 && tokenSold < 138216000) {
            _price += price; 
        }
        uint amount = msg.value * _price;
        tokenSold += amount / 1 ether;
        tokenReward.transferFrom(owner, msg.sender, amount);
        emit FundTransfer(msg.sender, amount, true);
        owner.transfer(msg.value);
    }
}
