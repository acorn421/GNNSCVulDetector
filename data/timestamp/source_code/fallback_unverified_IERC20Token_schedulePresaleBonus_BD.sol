/*
 * ===== SmartInject Injection Details =====
 * Function      : schedulePresaleBonus
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 8 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a stateful, multi-transaction timestamp dependence vulnerability. The exploit requires: 1) Owner calls schedulePresaleBonus() to set time-based bonus period, 2) Attacker participates during bonus period via participateInPresaleBonus(), 3) Attacker claims bonus tokens via claimPresaleBonus() after period ends. The vulnerability allows miners to manipulate block.timestamp within acceptable bounds to extend bonus periods or claim bonuses at favorable times. The state (presaleBonusBalance, presaleParticipants) persists between transactions, making this a multi-transaction attack requiring coordinated timestamp manipulation across multiple blocks.
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

    // State variables for presale bonus system
    uint256 public presaleBonusStart;
    uint256 public presaleBonusEnd;
    uint256 public presaleBonusRate;
    mapping(address => uint256) public presaleBonusBalance;
    mapping(address => bool) public presaleParticipants;

    constructor(IERC20Token _tokenContract, uint256 LUPXperETH) public {
        owner = msg.sender ;
        tokenContract = _tokenContract ;
        LUPXPrice = LUPXperETH ; 
    }

    // Schedule presale bonus period with timestamp-dependent logic
    function schedulePresaleBonus(uint256 _durationMinutes, uint256 _bonusRate) public onlyOwner {
        require(_durationMinutes > 0 && _bonusRate > 0);
        
        // Vulnerable: Uses block.timestamp for critical time calculations
        presaleBonusStart = block.timestamp;
        presaleBonusEnd = block.timestamp + (_durationMinutes * 60);
        presaleBonusRate = _bonusRate;
        
        emit priceAdjusted(LUPXPrice, LUPXPrice * (100 + _bonusRate) / 100);
    }
    
    // Participate in presale bonus - requires multiple transactions to exploit
    function participateInPresaleBonus() public payable {
        require(msg.value > 0);
        
        // Vulnerable: Timestamp dependence allows manipulation
        // Miners can manipulate block.timestamp within bounds
        require(block.timestamp >= presaleBonusStart && block.timestamp <= presaleBonusEnd);
        
        uint256 bonusAmount = safeMultiply(msg.value, presaleBonusRate) / 100;
        presaleBonusBalance[msg.sender] += bonusAmount;
        presaleParticipants[msg.sender] = true;
        
        // State persists between transactions
        emit sold(msg.sender, bonusAmount);
    }
    
    // Claim presale bonus tokens - second transaction required
    function claimPresaleBonus() public {
        require(presaleParticipants[msg.sender]);
        require(presaleBonusBalance[msg.sender] > 0);
        
        // Vulnerable: Another timestamp check that can be manipulated
        // Exploitation requires coordinated timestamp manipulation across multiple blocks
        require(block.timestamp > presaleBonusEnd);
        
        uint256 bonusTokens = presaleBonusBalance[msg.sender];
        presaleBonusBalance[msg.sender] = 0;
        
        require(tokenContract.balanceOf(this) >= bonusTokens);
        tokenContract.transfer(msg.sender, bonusTokens);
        
        tokensSold += bonusTokens / 10**18;
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
