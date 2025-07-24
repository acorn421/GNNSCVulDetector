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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through a grace period mechanism that can be manipulated across multiple transactions. The vulnerability requires:
 * 
 * 1. **State Accumulation**: Multiple state variables track repossession attempts, grace period end time, and last attempt timestamp
 * 2. **Multi-Transaction Exploitation**: 
 *    - First transaction initializes grace period
 *    - Subsequent transactions can extend grace period by manipulating block timestamps
 *    - Requires coordination across multiple blocks to maintain grace period extension
 * 3. **Timestamp Manipulation**: Uses `now` (block.timestamp) for critical timing decisions that can be influenced by miners
 * 4. **Realistic Attack Vector**: Borrowers can collaborate with miners to manipulate block timestamps within the 5-minute buffer window to continuously extend grace periods
 * 
 * The vulnerability is realistic because it implements a seemingly reasonable grace period mechanism but relies on manipulable block timestamps for critical timing decisions. The multi-transaction nature makes it more sophisticated than simple timestamp dependencies, requiring sustained manipulation across multiple blocks to be effective.
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
    
    // Variables for repossession extension logic (timestamp dependence vulnerability)
    uint256 public gracePeriodEnd;
    uint256 public repossessionAttempts;
    uint256 public lastRepossessionAttempt;
    uint256 constant GRACE_PERIOD_EXTENSION = 1 days;
    uint256 constant MIN_ATTEMPT_INTERVAL = 1 hours;

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
    // Additional state variables needed (add to contract):
    // uint256 public gracePeriodEnd;
    // uint256 public repossessionAttempts;
    // uint256 public lastRepossessionAttempt;
    // uint256 constant GRACE_PERIOD_EXTENSION = 1 days;
    // uint256 constant MIN_ATTEMPT_INTERVAL = 1 hours;

    function repossess() public {
        require(now > dueDate);
        
        // Initialize grace period on first repossession attempt
        if (repossessionAttempts == 0) {
            gracePeriodEnd = now + GRACE_PERIOD_EXTENSION;
            repossessionAttempts = 1;
            lastRepossessionAttempt = now;
            return; // Exit early on first attempt
        }
        
        // Enforce minimum interval between attempts
        require(now >= lastRepossessionAttempt + MIN_ATTEMPT_INTERVAL);
        
        // Check if still in grace period - extend if block timestamp is close to boundary
        if (now <= gracePeriodEnd) {
            // Vulnerable: Uses block.timestamp for critical timing decision
            // If block.timestamp is manipulated to be just before gracePeriodEnd,
            // this extends the grace period further
            if (gracePeriodEnd - now <= 300) { // 5 minutes buffer
                gracePeriodEnd = now + GRACE_PERIOD_EXTENSION;
            }
            repossessionAttempts++;
            lastRepossessionAttempt = now;
            return; // Still in grace period, cannot repossess
        }
        
        // Grace period has ended, proceed with repossession
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        require(token.transfer(lender, collateralAmount));
        selfdestruct(lender);
    }
}
