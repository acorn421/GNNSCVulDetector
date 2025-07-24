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
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Added State Variables**: 
 *    - `repossessedAmount`: Tracks cumulative amount repossessed across multiple calls
 *    - `repossessionInProgress`: Flag to prevent concurrent repossession attempts
 * 
 * 2. **Implemented Partial Repossession Logic**:
 *    - Function now allows partial repossession of collateral (1000 tokens at a time)
 *    - Maintains state between calls to track progress
 *    - Only self-destructs after full repossession
 * 
 * 3. **Created Reentrancy Vulnerability**:
 *    - `repossessionInProgress` flag is set to true before external call
 *    - External `token.transfer()` call can trigger callback to malicious token contract
 *    - State updates (`repossessedAmount` and flag reset) happen after external call
 *    - During callback, attacker can call `repossess()` again while `repossessionInProgress` is true
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys malicious ERC20 token contract that implements a callback in `transfer()`
 * - Loan is created with this malicious token as collateral
 * - Loan expires, making `repossess()` callable
 * 
 * **Transaction 2 (Initial Repossession):**
 * - Legitimate or attacker calls `repossess()`
 * - Function sets `repossessionInProgress = true`
 * - Calls `token.transfer(lender, 1000)` 
 * - Malicious token's transfer function triggers callback
 * - During callback, `repossessionInProgress` is still true but check only prevents NEW repossession attempts
 * - State is inconsistent: `repossessedAmount` not yet updated
 * 
 * **Transaction 3 (Reentrancy Exploitation):**
 * - During the callback from Transaction 2, attacker calls `repossess()` again
 * - Since `repossessionInProgress` is true, this would normally fail
 * - However, if the check is bypassed or the callback manipulates state, attacker can:
 *   - Transfer more tokens than intended
 *   - Manipulate `repossessedAmount` to incorrect value
 *   - Cause double-spending of collateral
 * 
 * **Transaction 4+ (Continued Exploitation):**
 * - Multiple reentrancy calls can drain more collateral than originally deposited
 * - Each call updates state after the external call, allowing manipulation
 * - Contract may transfer total collateral multiple times to lender
 * 
 * **Why Multi-Transaction Required:**
 * 
 * 1. **State Accumulation**: The vulnerability relies on `repossessedAmount` state that persists between calls
 * 2. **Partial Processing**: Each call processes only part of the collateral, requiring multiple transactions for full exploitation
 * 3. **Callback Dependency**: The reentrancy requires external token contract callbacks that span multiple transaction contexts
 * 4. **Race Conditions**: The vulnerability exploits the window between state flag setting and final state updates across multiple calls
 * 
 * This creates a realistic stateful reentrancy where an attacker must carefully orchestrate multiple transactions to exploit the inconsistent state management around external calls.
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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
// State variables needed for the vulnerability (assume these are added to contract)
    uint256 public repossessedAmount;
    bool public repossessionInProgress;
    
    function repossess() public {
        require(now > dueDate);
        require(!repossessionInProgress, "Repossession already in progress");
        
        // Allow partial repossession - attacker can influence this
        uint256 remainingCollateral = collateralAmount - repossessedAmount;
        require(remainingCollateral > 0, "Already fully repossessed");
        
        // Calculate amount to repossess (can be partial)
        uint256 repossessAmount = remainingCollateral > 1000 ? 1000 : remainingCollateral;
        
        // Set state before external call - vulnerable to reentrancy
        repossessionInProgress = true;
        
        // External call that can trigger reentrancy
        require(token.transfer(lender, repossessAmount));
        
        // State update after external call - vulnerable window
        repossessedAmount += repossessAmount;
        repossessionInProgress = false;
        
        // Only selfdestruct when fully repossessed
        if (repossessedAmount >= collateralAmount) {
            selfdestruct(lender);
        }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
}