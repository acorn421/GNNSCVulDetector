/*
 * ===== SmartInject Injection Details =====
 * Function      : endLUPXSale
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced stateful, multi-transaction reentrancy vulnerability by: 1) Adding 'saleEnded' state variable check, 2) Replacing direct transfer with low-level call that allows reentrancy, 3) Moving state update (saleEnded = true) after external call, creating vulnerability window where attacker can reenter before state is updated. This requires multiple transactions: first to trigger the vulnerability, subsequent calls to exploit the state inconsistency before saleEnded is set to true.
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
    bool saleEnded = false;
    
    event sold(address buyer, uint256 amount) ;
    event priceAdjusted(uint256 oldPrice, uint256 newPrice) ;
    event endOfSale(uint256 timeStamp) ; 

    constructor(IERC20Token _tokenContract, uint256 LUPXperETH) public {
        owner = msg.sender ;
        tokenContract = _tokenContract ;
        LUPXPrice = LUPXperETH ; 
    }
    
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        require(!saleEnded, "Sale already ended");
        require(tokenContract.transfer(owner, tokenContract.balanceOf(this)));
        
        // External call before state update - creates reentrancy window
        (bool success, ) = msg.sender.call.value(address(this).balance)("");
        require(success, "Transfer failed");
        
        // State update after external call - vulnerability window
        saleEnded = true;
        emit endOfSale(now);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
}