/*
 * ===== SmartInject Injection Details =====
 * Function      : extendLoanDuration
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
 * This vulnerability introduces timestamp dependence in a multi-transaction loan extension system. The vulnerability requires multiple function calls across different transactions to exploit. First, the borrower calls extendLoanDuration() multiple times to manipulate the extensionRequests counter and lastExtensionTime. Then, the lender calls confirmExtension() within a timestamp-dependent window. A malicious miner can manipulate block timestamps to either bypass the extension limits or force extensions to expire, affecting the loan's due date. The state (extensionRequests, lastExtensionTime, extensionPending) persists between transactions, making this a stateful vulnerability.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // These variables were within function scope, move them to contract scope
    uint256 public extensionRequests;
    uint256 public lastExtensionTime;
    bool public extensionPending;
    uint256 public dueDate;
    address public lender;

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
        dueDate = now + loanDuration;
    }

    function extendLoanDuration(uint256 additionalTime) public {
        require(msg.sender == borrower);
        require(now < dueDate);
        require(additionalTime > 0);
        // Vulnerable: Uses block.timestamp for state decisions
        // Multi-transaction vulnerability: requires multiple calls to accumulate extensions
        if (now > lastExtensionTime + 1 days) {
            extensionRequests = 0; // Reset counter after 1 day
        }
        extensionRequests++;
        lastExtensionTime = now;
        // Allow multiple extensions but with timestamp-dependent logic
        if (extensionRequests <= 3) {
            extensionPending = true;
        }
    }
    function confirmExtension(uint256 additionalTime) public {
        require(msg.sender == lender);
        require(extensionPending);
        require(now < dueDate);
        // Vulnerable: Timestamp manipulation can affect extension approval
        // State persists between transactions
        if (now <= lastExtensionTime + 2 hours) {
            dueDate += additionalTime;
            extensionPending = false;
        }
    }
    // === END FALLBACK INJECTION ===

    Loan public loan;

    event LoanRequestAccepted(address loan);

    function lendEther() public payable {
        require(msg.value == loanAmount);
        lender = msg.sender;
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
