/*
 * ===== SmartInject Injection Details =====
 * Function      : repossess
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through a grace period mechanism. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **State Variables Added**: Added gracePeriodActive, gracePeriodStart, lastRepossessionAttempt mapping, and penalty calculation parameters that persist between transactions.
 * 
 * 2. **Multi-Transaction Requirement**: 
 *    - First call sets gracePeriodActive=true and gracePeriodStart=now, then returns without repossessing
 *    - Subsequent calls must wait for grace period to pass before actual repossession
 *    - This creates a mandatory 7-day delay requiring at least 2 separate transactions
 * 
 * 3. **Timestamp Dependence Vulnerabilities**:
 *    - Uses block.timestamp (now) for critical grace period calculations
 *    - Penalty calculations depend on timestamp differences that miners can manipulate
 *    - Block.number used for additional "randomness" in penalty reduction logic
 *    - No proper validation of timestamp authenticity or manipulation resistance
 * 
 * 4. **Exploitation Scenarios**:
 *    - Miners can manipulate timestamps within ~15 second windows to reduce penalties
 *    - Attackers can time their repossession attempts to minimize penalties by exploiting block.number differences
 *    - Grace period timing can be manipulated to create favorable conditions for lenders
 *    - The penalty calculation creates economic incentives for timestamp manipulation
 * 
 * 5. **Multi-Transaction Exploitation**:
 *    - Transaction 1: Call repossess() to start grace period
 *    - Wait for optimal timing conditions
 *    - Transaction 2: Call repossess() again when timestamp manipulation is most favorable
 *    - Multiple attempts can be made with different timing strategies to minimize penalties or maximize gains
 * 
 * The vulnerability maintains the original function's core purpose while introducing realistic timing-dependent features that require state accumulation across multiple transactions to exploit effectively.
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

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping(address => uint256) public lastRepossessionAttempt;
    uint256 public gracePeriodDuration = 7 days;
    uint256 public penaltyRate = 10; // 10% per day
    uint256 public maxPenalty = 50; // 50% max penalty
    bool public gracePeriodActive = false;
    uint256 public gracePeriodStart;
    
    function repossess() public {
        require(now > dueDate);
        
        // First attempt: Start grace period
        if (!gracePeriodActive) {
            gracePeriodActive = true;
            gracePeriodStart = now;
            lastRepossessionAttempt[msg.sender] = block.number;
            return;
        }
        
        // Subsequent attempts: Check if grace period has passed
        require(now >= gracePeriodStart + gracePeriodDuration);
        
        // Calculate penalty based on block.timestamp differences
        uint256 daysSinceGrace = (now - gracePeriodStart) / 1 days;
        uint256 penalty = (daysSinceGrace * penaltyRate * collateralAmount) / 100;
        
        if (penalty > (maxPenalty * collateralAmount) / 100) {
            penalty = (maxPenalty * collateralAmount) / 100;
        }
        
        // Use block.number differences for additional randomness (vulnerable)
        uint256 blockDiff = block.number - lastRepossessionAttempt[msg.sender];
        if (blockDiff < 10) {
            penalty = penalty / 2; // Reduce penalty if called too quickly
        }
        
        uint256 finalAmount = collateralAmount + penalty;
        require(token.transfer(lender, finalAmount));
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        selfdestruct(lender);
    }
}