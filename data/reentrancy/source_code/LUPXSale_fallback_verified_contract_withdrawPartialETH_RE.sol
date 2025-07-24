/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawPartialETH
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * This vulnerability introduces a stateful, multi-transaction reentrancy attack. The vulnerability requires: 1) First transaction: Owner calls requestWithdrawal() to set up pending withdrawal state, 2) Second transaction: Owner calls withdrawPartialETH() which makes external call before fully completing state updates, 3) The external call can reenter and exploit the inconsistent state. The attack requires multiple transactions and persistent state (pendingWithdrawals mapping) to work.
 */
pragma solidity ^0.4.25;

interface IERC20Token {                                     
    function balanceOf(address owner) external returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function decimals() external returns (uint256);
}

contract LUPXSale {
    IERC20Token public tokenContract ;
    address owner ;
    uint256 public tokensSold ;
    uint256 public LUPXPrice ;
    
    event sold(address buyer, uint256 amount) ;
    event priceAdjusted(uint256 oldPrice, uint256 newPrice) ;
    event endOfSale(uint256 timeStamp) ;

    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    mapping(address => uint256) public pendingWithdrawals;
    bool private withdrawalInProgress = false;
    // === END FALLBACK INJECTION ===

    constructor(IERC20Token _tokenContract, uint256 LUPXperETH) public {
        owner = msg.sender ;
        tokenContract = _tokenContract ;
        LUPXPrice = LUPXperETH ; 
    }

    // === FALLBACK INJECTION: Reentrancy ===
    function requestWithdrawal(uint256 amount) public onlyOwner {
        require(amount <= address(this).balance, "Insufficient balance");
        require(amount > 0, "Amount must be greater than 0");
        pendingWithdrawals[msg.sender] += amount;
    }
    
    function withdrawPartialETH(uint256 amount) public onlyOwner {
        require(!withdrawalInProgress, "Withdrawal already in progress");
        require(pendingWithdrawals[msg.sender] >= amount, "Insufficient pending withdrawal");
        require(amount > 0, "Amount must be greater than 0");
        
        withdrawalInProgress = true;
        pendingWithdrawals[msg.sender] -= amount;
        
        // Vulnerable to reentrancy - external call before state update completion
        msg.sender.call.value(amount)("");
        
        withdrawalInProgress = false;
    }
    // === END FALLBACK INJECTION ===

    modifier onlyOwner() {
        require(msg.sender == owner) ; 
        _;
    }

    function safeMultiply(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0 ;
        } else {
            uint256 c = a * b ;
            assert(c / a == b) ;
            return c ;
        }
    }

    function () public payable {
        uint256 soldAmount = 0 ; 
        
        if (msg.value <= 1 ether) {
            soldAmount = safeMultiply(msg.value, LUPXPrice) ;
        }
        else {
            soldAmount = safeMultiply(msg.value*3/2, LUPXPrice) ;
        }
        require(tokenContract.balanceOf(this) >= soldAmount) ;
        tokenContract.transfer(msg.sender, soldAmount) ;
        
        tokensSold += soldAmount/10**18 ; 
        emit sold(msg.sender, soldAmount/10**18) ; 

    }
    
    function withdrawETH() public  onlyOwner {
        msg.sender.transfer(address(this).balance) ;  
    }

    function endLUPXSale() public onlyOwner { 
        require(tokenContract.transfer(owner, tokenContract.balanceOf(this))) ;
        msg.sender.transfer(address(this).balance) ;
        emit endOfSale(now) ; 
    }
}
