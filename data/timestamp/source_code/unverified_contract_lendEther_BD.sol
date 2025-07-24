/*
 * ===== SmartInject Injection Details =====
 * Function      : lendEther
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by implementing an "early lender discount" mechanism. The vulnerability works as follows:
 * 
 * **Specific Changes Made:**
 * 1. Added state variables to track lender interaction times and discount parameters
 * 2. Modified the function to record `lenderFirstInteractionTime[msg.sender]` on first interaction
 * 3. Added logic to calculate `adjustedPayoffAmount` based on timing within a discount window
 * 4. Applied early lender discount if the current timestamp is within the discount window from first interaction
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1 (Setup)**: Attacker calls any function that triggers timestamp recording or makes a small test transaction to establish their `lenderFirstInteractionTime`
 * 2. **Transaction 2 (Exploitation)**: Within the 5-minute discount window, attacker calls `lendEther()` to receive a 10% discount on the payoff amount, effectively getting better loan terms
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability requires state persistence (`lenderFirstInteractionTime` mapping) between transactions
 * - The first transaction establishes the baseline timestamp for the discount calculation
 * - The second transaction must occur within the time window to exploit the favorable terms
 * - The exploit cannot be performed in a single transaction because the timestamp comparison depends on previously stored state
 * 
 * **Real-World Exploitation Impact:**
 * - Attackers can manipulate timing to get preferential loan terms
 * - The discount mechanism creates an unfair advantage for users who can time their transactions
 * - Block timestamp manipulation by miners could further exploit this vulnerability
 * - The vulnerability enables systematic exploitation where attackers can repeatedly benefit from the discount mechanism across multiple loan requests
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

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping(address => uint256) public lenderFirstInteractionTime;
    uint256 public lenderDiscountWindow = 300; // 5 minutes in seconds
    uint256 public earlyLenderDiscountRate = 90; // 10% discount (90% of original rate)
    
    function lendEther() public payable {
        require(msg.value == loanAmount);
        
        // Record first interaction time for new lenders
        if (lenderFirstInteractionTime[msg.sender] == 0) {
            lenderFirstInteractionTime[msg.sender] = block.timestamp;
        }
        
        // Calculate adjusted payoff amount based on timing
        uint256 adjustedPayoffAmount = payoffAmount;
        
        // Apply early lender discount if within discount window
        if (block.timestamp <= lenderFirstInteractionTime[msg.sender] + lenderDiscountWindow) {
            adjustedPayoffAmount = (payoffAmount * earlyLenderDiscountRate) / 100;
        }
        
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        loan = new Loan(
            msg.sender,
            borrower,
            token,
            collateralAmount,
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            adjustedPayoffAmount,
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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