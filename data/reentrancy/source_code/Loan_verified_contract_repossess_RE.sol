/*
 * ===== SmartInject Injection Details =====
 * Function      : repossess
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added persistent state variables** (repossessionStarted, repossessionInitiator, repossessionStartTime, repossessionCompleted) that track the repossession process across multiple transactions
 * 2. **Split repossession into two phases**: initialization and completion, requiring separate transaction calls
 * 3. **Introduced external callback** to lender contract after token transfer but before state finalization
 * 4. **Moved state updates after external calls**, creating a reentrancy window where the callback can re-enter the function
 * 
 * **Multi-Transaction Exploitation Path:**
 * - **Transaction 1**: Attacker calls repossess() to initialize (sets repossessionStarted = true)
 * - **Transaction 2**: After delay, attacker calls repossess() again to complete, triggering the vulnerable callback
 * - **During callback**: Lender contract can re-enter repossess() or other functions since repossessionCompleted is still false
 * - **Exploitation**: Multiple token transfers or state manipulations possible before final state update
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the initial state setup (repossessionStarted = true) to persist from Transaction 1
 * - The repossessionDelay enforces a time gap, making single-transaction exploitation impossible
 * - The reentrancy window only opens during the completion phase, which can only be reached after the initialization phase
 * - State accumulation across transactions creates the conditions necessary for the callback-based reentrancy attack
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

    // Added state variables needed for repossess logic
    bool public repossessionStarted;
    address public repossessionInitiator;
    uint256 public repossessionStartTime;
    uint256 public repossessionDelay = 3 days; // Default delay value, can adjust as necessary
    bool public repossessionCompleted;
    
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
        // Initialize new variables
        repossessionStarted = false;
        repossessionInitiator = address(0);
        repossessionStartTime = 0;
        repossessionCompleted = false;
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Begin repossession process if not already started
        if (!repossessionStarted) {
            repossessionStarted = true;
            repossessionInitiator = msg.sender;
            repossessionStartTime = now;
            return;
        }
        
        // Ensure minimum time has passed for validation
        require(now >= repossessionStartTime + repossessionDelay);
        require(msg.sender == repossessionInitiator);
        
        // External call to token contract before state finalization
        if (token.transfer(lender, collateralAmount)) {
            // Callback to lender contract for confirmation
            if (lender.call.value(0)(bytes4(keccak256("onRepossessionComplete(address,uint256)")), borrower, collateralAmount)) {
                // State update after external calls - vulnerable to reentrancy
                repossessionCompleted = true;
                selfdestruct(lender);
            }
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
}
