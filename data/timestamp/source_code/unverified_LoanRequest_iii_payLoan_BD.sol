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
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through a grace period mechanism that stores critical timing information across transactions. The vulnerability allows manipulation of payment deadlines and penalties through strategic timestamp manipulation across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added grace period logic that allows borrowers to extend deadlines within a time window
 * 2. Introduced state variables that store timestamps from previous transactions (lastGraceRequest)
 * 3. Implemented time-based penalty calculation using stored timestamps
 * 4. Created conditions where block timestamp manipulation affects financial outcomes
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **Transaction 1 (Setup)**: Borrower calls payLoan() near deadline to trigger grace period extension, storing malicious timestamp in lastGraceRequest
 * 2. **Transaction 2 (Exploitation)**: Miner manipulates block.timestamp to reduce time elapsed calculation, minimizing penalties or even allowing payment with reduced amounts
 * 
 * **Why Multiple Transactions Required:**
 * - The vulnerability requires storing timestamp state in Transaction 1 (lastGraceRequest)
 * - Exploitation happens in Transaction 2 when this stored timestamp is used for penalty calculation
 * - The stored timestamp from a previous block can be manipulated by miners to affect future calculations
 * - Single transaction exploitation is impossible because the vulnerability depends on the relationship between stored timestamps and current block timestamp
 * 
 * **State Persistence:**
 * - lastGraceRequest persists between transactions
 * - gracePeriodUsed tracks usage across multiple calls
 * - dueDate can be modified and affects subsequent transactions
 * 
 * This creates a realistic scenario where loan payment timing and penalties can be manipulated through coordinated timestamp manipulation across multiple transactions, making it a genuine multi-transaction timestamp dependence vulnerability.
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

    // Added missing state variables for timestamp dependence logic
    uint256 public lastGraceRequest;
    bool public gracePeriodUsed;
    uint256 public constant gracePeriodWindow = 1 days;
    uint256 public constant gracePeriodExtension = 3 days;
    uint256 public constant penaltyThreshold = 2 days;
    uint256 public constant penaltyRate = 1 ether / 10000; // Arbitrary penalty rate for example

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
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Grace period mechanism - borrower can extend deadline if within grace window
        if (now > dueDate - gracePeriodWindow && !gracePeriodUsed) {
            if (msg.sender == borrower) {
                lastGraceRequest = now;
                gracePeriodUsed = true;
                dueDate = now + gracePeriodExtension;
                return; // Exit early to allow extension
            }
        }
        
        // Time-based penalty calculation using accumulated timestamps
        uint256 finalPayoff = payoffAmount;
        if (lastGraceRequest > 0) {
            // Vulnerable: uses stored timestamp from previous transaction
            uint256 timeElapsed = now - lastGraceRequest;
            if (timeElapsed > penaltyThreshold) {
                finalPayoff = payoffAmount + (timeElapsed * penaltyRate);
            }
        }
        
        require(msg.value >= finalPayoff);
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
