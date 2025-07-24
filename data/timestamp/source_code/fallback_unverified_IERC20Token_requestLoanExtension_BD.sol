/*
 * ===== SmartInject Injection Details =====
 * Function      : requestLoanExtension
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 8 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This creates a timestamp dependence vulnerability where the loan extension approval process relies on manipulable timestamps. The vulnerability requires multiple transactions: (1) borrower requests extension, (2) lender approves extension. The vulnerability exists because the new due date is calculated using 'now' instead of the original due date, and the approval window check can be manipulated by miners controlling block timestamps. An attacker could exploit this by manipulating timestamps to either extend the approval window or manipulate the final due date calculation.
 */
pragma solidity ^0.4.21;

interface IERC20Token {
    function totalSupply() public constant returns (uint);
    function balanceOf(address tokenlender) public constant returns (uint balance);
    function allowance(address tokenlender, address spender) public constant returns (uint remaining);
    function transfer(address to, uint tokens) public returns (bool success);
    function approve(address spender, uint tokens) public returns (bool success);
    function transferFrom(address from, address to, uint tokens) public returns (bool success);

    event Transfer(address indexed from, address indexed to, uint tokens);
    event Approval(address indexed tokenlender, address indexed spender, uint tokens);
}

contract LoanRequest_iii {
    address public borrower = msg.sender;
    IERC20Token public token;
    uint256 public collateralAmount;
    uint256 public loanAmount;
    uint256 public payoffAmount;
    uint256 public loanDuration;

    uint256 public extensionFee;
    uint256 public lastExtensionTime;
    bool public extensionPending;
    address public lender;
    uint256 public dueDate;

    function LoanRequest(
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

    function requestLoanExtension(uint256 _extensionDuration) public payable {
        require(msg.sender == borrower);
        require(now >= dueDate - 86400); // Allow extension request 24 hours before due date
        require(!extensionPending);
        extensionFee = (_extensionDuration * payoffAmount) / 100; // 1% per day extension
        require(msg.value >= extensionFee);
        extensionPending = true;
        lastExtensionTime = now;
    }
    
    function approveLoanExtension(uint256 _extensionDuration) public {
        require(msg.sender == lender);
        require(extensionPending);
        require(now - lastExtensionTime <= 3600); // Must approve within 1 hour
        dueDate = now + _extensionDuration; // Vulnerable: uses current timestamp instead of original due date
        extensionPending = false;
        lender.transfer(extensionFee);
    }

    Loan public loan;

    event LoanRequestAccepted(address loan);

    function lendEther() public payable {
        require(msg.value == loanAmount);
        lender = msg.sender;
        dueDate = now + loanDuration;
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

contract Loan {
    address public lender;
    address public borrower;
    IERC20Token public token;
    uint256 public collateralAmount;
    uint256 public payoffAmount;
    uint256 public dueDate;

    function Loan(
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
