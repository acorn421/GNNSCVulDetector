/*
 * ===== SmartInject Injection Details =====
 * Function      : requestWithdrawal
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
 * Multi-transaction reentrancy vulnerability in withdrawal system. The vulnerability requires: 1) First transaction to call requestWithdrawal() to set up the withdrawal request state, 2) Second transaction to call processWithdrawal() which performs external call before updating state variables. An attacker can exploit this by implementing a fallback function that recursively calls processWithdrawal() to drain funds. The vulnerability is stateful as it depends on the withdrawalRequested and pendingWithdrawals mappings being set in a previous transaction.
 */
pragma solidity ^0.4.24;

library SafeMath {
    function mul(uint256 a, uint256 b) internal pure returns (uint256 c) {
        if (a == 0) {
            return 0;
        }
        c = a * b;
        require(c / a == b, "SafeMath mul failed");
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256 c) {
        return a / b;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a, "SafeMath sub failed");
        return a - b;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256 c) {
        c = a + b;
        require(c >= a, "SafeMath add failed");
        return c;
    }
}

contract Ownable {
    address public owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "You are not owner.");
        _;
    }

    function transferOwnership(address _newOwner) public onlyOwner {
        require(_newOwner != address(0), "Invalid address.");

        owner = _newOwner;

        emit OwnershipTransferred(owner, _newOwner);
    }
}

contract Foundation is Ownable {
    using SafeMath for uint256;

    string public name = "Fomo3D Foundation (Asia)";

    mapping(address => uint256) public depositOf;

    // === FALLBACK INJECTION: Reentrancy ===
    mapping(address => uint256) public pendingWithdrawals;
    mapping(address => bool) public withdrawalRequested;

    event WithdrawalRequested(address indexed who, uint256 amount);
    // === END FALLBACK INJECTION ===

    struct Member {
        address who;
        uint256 shares;
    }
    Member[] private members;

    event Deposited(address indexed who, uint256 amount);
    event Withdrawn(address indexed who, uint256 amount);

    constructor() public {
        members.push(Member(address(0), 0));

        members.push(Member(0x05dEbE8428CAe653eBA92a8A887CCC73C7147bB8, 60));
        members.push(Member(0xF53e5f0Af634490D33faf1133DE452cd9fF987e1, 20));
        members.push(Member(0x34d26e1325352d7b3f91df22ae97894b0c5343b7, 20));
    }

    function() public payable {
        deposit();
    }

    function deposit() public payable {
        uint256 amount = msg.value;
        require(amount > 0, "Deposit failed - zero deposits not allowed");

        for (uint256 i = 1; i < members.length; i++) {
            if (members[i].shares > 0) {
                depositOf[members[i].who] = depositOf[members[i].who].add(amount.mul(members[i].shares).div(100));
            }
        }

        emit Deposited(msg.sender, amount);
    }

    function withdraw(address _who) public {
        uint256 amount = depositOf[_who];
        require(amount > 0 && amount <= address(this).balance, "Insufficient amount.");

        depositOf[_who] = depositOf[_who].sub(amount);

        _who.transfer(amount);

        emit Withdrawn(_who, amount);
    }

    function setMember(address _who, uint256 _shares) public onlyOwner {
        uint256 memberIndex = 0;
        uint256 sharesSupply = 100;
        for (uint256 i = 1; i < members.length; i++) {
            if (members[i].who == _who) {
                memberIndex = i;
            } else if (members[i].shares > 0) {
                sharesSupply = sharesSupply.sub(members[i].shares);
            }
        }
        require(_shares <= sharesSupply, "Insufficient shares.");

        if (memberIndex > 0) {
            members[memberIndex].shares = _shares;
        } else {
            members.push(Member(_who, _shares));
        }
    }

    // Vulnerable: External call before state update
    function requestWithdrawal(uint256 _amount) public {
        require(_amount > 0, "Amount must be greater than 0");
        require(depositOf[msg.sender] >= _amount, "Insufficient deposit balance");
        require(!withdrawalRequested[msg.sender], "Withdrawal already requested");

        pendingWithdrawals[msg.sender] = _amount;
        withdrawalRequested[msg.sender] = true;

        emit WithdrawalRequested(msg.sender, _amount);
    }

    function processWithdrawal() public {
        require(withdrawalRequested[msg.sender], "No withdrawal request found");
        require(pendingWithdrawals[msg.sender] > 0, "No pending withdrawal");

        uint256 amount = pendingWithdrawals[msg.sender];
        require(amount <= address(this).balance, "Contract has insufficient balance");

        // Vulnerable: External call before state update
        if (msg.sender.call.value(amount)()) {
            // State updates happen after external call - reentrancy vulnerability
            depositOf[msg.sender] = depositOf[msg.sender].sub(amount);
            pendingWithdrawals[msg.sender] = 0;
            withdrawalRequested[msg.sender] = false;

            emit Withdrawn(msg.sender, amount);
        }
    }
}