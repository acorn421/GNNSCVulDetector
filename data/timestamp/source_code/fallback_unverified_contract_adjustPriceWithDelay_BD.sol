/*
 * ===== SmartInject Injection Details =====
 * Function      : adjustPriceWithDelay
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence that requires multiple transactions to exploit. The vulnerability exists because miners can manipulate the 'now' timestamp within certain bounds. An attacker who is also a miner can: 1) Call requestPriceAdjustment() to initiate a price change, 2) Mine the block with a manipulated timestamp to make the delay period appear shorter, 3) Call executePriceChange() prematurely to execute the price change before the intended delay period. This requires multiple transactions and state persistence (priceChangeRequested, priceChangeTimestamp, pendingPriceChange) to exploit.
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

    uint256 public priceAdjustmentDelay = 3600; // 1 hour delay
    uint256 public pendingPriceChange;
    uint256 public priceChangeTimestamp;
    bool public priceChangeRequested;

    constructor(IERC20Token _tokenContract, uint256 LUPXperETH) public {
        owner = msg.sender ;
        tokenContract = _tokenContract ;
        LUPXPrice = LUPXperETH ; 
    }

    function requestPriceAdjustment(uint256 newPrice) public onlyOwner {
        require(newPrice > 0, "Price must be positive");
        pendingPriceChange = newPrice;
        priceChangeTimestamp = now + priceAdjustmentDelay;
        priceChangeRequested = true;
        emit priceAdjusted(LUPXPrice, newPrice);
    }
    
    function executePriceChange() public onlyOwner {
        require(priceChangeRequested, "No price change requested");
        require(now >= priceChangeTimestamp, "Price change delay not met");
        
        uint256 oldPrice = LUPXPrice;
        LUPXPrice = pendingPriceChange;
        priceChangeRequested = false;
        pendingPriceChange = 0;
        priceChangeTimestamp = 0;
        
        emit priceAdjusted(oldPrice, LUPXPrice);
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
        require(tokenContract.transfer(owner, tokenContract.balanceOf(this))) ;
        msg.sender.transfer(address(this).balance) ;
        emit endOfSale(now) ; 
    }
}