/*
 * ===== SmartInject Injection Details =====
 * Function      : lendEther
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
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added loan existence check**: The function now checks if `loan == address(0)` before creating a new loan, allowing multiple calls to the same function for the same loan request.
 * 
 * 2. **Reordered operations**: Moved the `borrower.transfer(loanAmount)` before the `token.transferFrom()` call, violating the Checks-Effects-Interactions pattern.
 * 
 * 3. **Created multi-transaction exploitation path**: 
 *    - **Transaction 1**: Lender calls `lendEther()`, creates loan, transfers ether to borrower
 *    - **During Transaction 1**: Malicious borrower contract's receive/fallback function triggers reentrancy
 *    - **Reentrant call**: Borrower can call `lendEther()` again (with different lender) since loan already exists
 *    - **Transaction 2+**: Additional lenders can be drained by the same borrower using the existing loan
 * 
 * 4. **Stateful vulnerability**: The persistent `loan` state variable allows the borrower to exploit multiple lenders across different transactions, as the loan is created once but can be used to drain multiple lenders.
 * 
 * **Multi-Transaction Exploitation Scenario**:
 * - **Setup**: Borrower creates a malicious contract that implements receive() to call lendEther() again
 * - **Transaction 1**: Lender A calls lendEther() → Creates loan → Transfers ether to malicious borrower → Borrower's receive() triggers reentrancy
 * - **Reentrant call**: During Transaction 1, the borrower can manipulate state or call other functions
 * - **Transaction 2**: Lender B calls lendEther() → Loan already exists → Transfers ether to borrower → Only one collateral transfer occurs
 * - **Result**: Multiple lenders lose ether, but borrower only provides collateral once
 * 
 * This creates a stateful vulnerability where the loan state persists between transactions, allowing the borrower to exploit multiple lenders while only providing collateral once.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Create loan if not already created
        if (loan == address(0)) {
            loan = new Loan(
                msg.sender,
                borrower,
                token,
                collateralAmount,
                payoffAmount,
                loanDuration
            );
        }
        
        // VULNERABILITY: External call before state update - allows reentrancy
        // The borrower can re-enter this function during the transfer
        borrower.transfer(loanAmount);
        
        // State update happens AFTER external call - vulnerable to reentrancy
        require(token.transferFrom(borrower, loan, collateralAmount));
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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