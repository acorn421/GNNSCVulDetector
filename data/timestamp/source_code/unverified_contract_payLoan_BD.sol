/*
 * ===== SmartInject Injection Details =====
 * Function      : payLoan
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through grace period manipulation. The vulnerability requires:
 * 
 * 1. **State Variable**: Added `lastPaymentAttempt` to track when the first payment attempt occurred
 * 2. **Multi-Transaction Requirement**: 
 *    - Transaction 1: Borrower calls `payLoan()` before due date, setting `lastPaymentAttempt`
 *    - Transaction 2: Borrower can call `payLoan()` again after due date, exploiting the grace period calculation
 * 3. **Timestamp Manipulation**: The grace period calculation uses `now` in arithmetic operations, allowing miners to manipulate block timestamps to extend the payment window
 * 4. **State Persistence**: The `lastPaymentAttempt` timestamp persists between transactions, enabling the vulnerability
 * 
 * **Exploitation Scenario:**
 * - Borrower calls `payLoan()` just before due date (sets `lastPaymentAttempt`)
 * - Due date passes, but borrower can still pay due to grace period
 * - Miners can manipulate `block.timestamp` to extend the grace period artificially
 * - The longer the time between attempts, the longer the grace period becomes
 * 
 * **Why Multi-Transaction is Required:**
 * - Single transaction cannot exploit this because `lastPaymentAttempt` must be set in a previous transaction
 * - The vulnerability depends on the time difference between the first attempt and subsequent attempts
 * - State accumulation (`lastPaymentAttempt`) is essential for the exploit to work
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

    Loan public loan;

    event LoanRequestAccepted(address loan);

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

contract Loan {
    address public lender;
    address public borrower;
    IERC20Token public token;
    uint256 public collateralAmount;
    uint256 public payoffAmount;
    uint256 public dueDate;
    uint256 public lastPaymentAttempt;

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
        lastPaymentAttempt = 0;
    }

    event LoanPaid();

    function payLoan() public payable {
        require(now <= dueDate);
        require(msg.value == payoffAmount);
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====

        // Track payment timestamp for grace period calculation
        if (lastPaymentAttempt == 0) {
            lastPaymentAttempt = now;
        }
        
        // Allow grace period if this is a retry after initial attempt
        if (lastPaymentAttempt > 0 && now > dueDate) {
            uint256 gracePeriod = (now - lastPaymentAttempt) / 3600; // 1 hour per hour passed
            require(now <= dueDate + gracePeriod);
        }
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

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
