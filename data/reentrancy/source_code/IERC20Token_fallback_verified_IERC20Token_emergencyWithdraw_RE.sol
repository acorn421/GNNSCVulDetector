/*
 * ===== SmartInject Injection Details =====
 * Function      : emergencyWithdraw
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 9 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * This introduces a stateful reentrancy vulnerability that requires multiple transactions to exploit. First, an attacker must call requestEmergencyWithdrawal() to set up the withdrawal request and timestamp. Then, after the WITHDRAWAL_DELAY period passes, they can call emergencyWithdraw() and exploit the reentrancy vulnerability. The vulnerability exists because the external call happens before the state variables are reset, allowing recursive calls to drain funds. This is a realistic emergency withdrawal mechanism that would naturally exist in a loan contract.
 */
pragma solidity ^0.4.21;

interface IERC20Token {
    function totalSupply() external constant returns (uint);
    function balanceOf(address tokenlender) external constant returns (uint balance);
    function allowance(address tokenlender, address spender) external constant returns (uint remaining);
    function transfer(address to, uint tokens) external returns (bool success);
    function approve(address spender, uint tokens) external returns (bool success);
    function transferFrom(address from, address to, uint tokens) external returns (bool success);

    event Transfer(address indexed from, address indexed to, uint tokens);
    event Approval(address indexed tokenlender, address indexed spender, uint tokens);
}

contract Loan {
    address public lender;
    address public borrower;
    IERC20Token public token;
    uint256 public collateralAmount;
    uint256 public payoffAmount;
    uint256 public dueDate;

    constructor(
        address _lender,
        address _borrower,
        IERC20Token _token,
        uint256 _collateralAmount,
        uint256 _payoffAmount,
        uint256 loanDuration
    )
        public
    {
        lender = _lender;
        borrower = _borrower;
        token = _token;
        collateralAmount = _collateralAmount;
        payoffAmount = _payoffAmount;
        dueDate = now + loanDuration;
    }

    event LoanPaid();

    function payLoan() public payable {
        require(now <= dueDate);
        require(msg.value == payoffAmount);

        require(token.transfer(borrower, collateralAmount));
        emit LoanPaid();
        selfdestruct(lender);
    }

    function repossess() public {
        require(now > dueDate);

        require(token.transfer(lender, collateralAmount));
        selfdestruct(lender);
    }
}

contract LoanRequest_iii {
    address public borrower = msg.sender;
    IERC20Token public token;
    uint256 public collateralAmount;
    uint256 public loanAmount;
    uint256 public payoffAmount;
    uint256 public loanDuration;

    // === FALLBACK INJECTION: Reentrancy ===
    // Declare these here, outside function body
    mapping(address => uint256) public withdrawalRequests;
    mapping(address => uint256) public withdrawalTimestamps;
    uint256 public constant WITHDRAWAL_DELAY = 24 hours;

    Loan public loan;

    event LoanRequestAccepted(address loan);

    function requestEmergencyWithdrawal(uint256 amount) public {
        require(msg.sender == borrower || (loan != address(0) && msg.sender == loan.lender()));
        require(amount > 0);

        withdrawalRequests[msg.sender] = amount;
        withdrawalTimestamps[msg.sender] = now;
    }

    function emergencyWithdraw() public {
        require(withdrawalRequests[msg.sender] > 0);
        require(now >= withdrawalTimestamps[msg.sender] + WITHDRAWAL_DELAY);

        uint256 amount = withdrawalRequests[msg.sender];

        // Vulnerable pattern: external call before state update
        if (!msg.sender.call.value(amount)()) {
            revert();
        }

        // State update after external call - vulnerable to reentrancy
        withdrawalRequests[msg.sender] = 0;
        withdrawalTimestamps[msg.sender] = 0;
    }
    // === END FALLBACK INJECTION ===

    constructor(
        IERC20Token _token,
        uint256 _collateralAmount,
        uint256 _loanAmount,
        uint256 _payoffAmount,
        uint256 _loanDuration
    )
        public
    {
        token = _token;
        collateralAmount = _collateralAmount;
        loanAmount = _loanAmount;
        payoffAmount = _payoffAmount;
        loanDuration = _loanDuration;
    }

    function lendEther() public payable {
        require(msg.value == loanAmount);
        loan = new Loan(
            msg.sender,
            borrower,
            token,
            collateralAmount,
            payoffAmount,
            loanDuration
        );
        require(token.transferFrom(borrower, loan, collateralAmount));
        borrower.transfer(loanAmount);
        emit LoanRequestAccepted(loan);
    }
}
