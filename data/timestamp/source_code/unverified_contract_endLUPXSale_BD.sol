/*
 * ===== SmartInject Injection Details =====
 * Function      : endLUPXSale
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by implementing a three-phase sale ending process:
 * 
 * 1. **First Transaction**: Sets `saleEndTimestamp` to current time + 24 hours, creating a grace period
 * 2. **Second Transaction**: Confirms sale end within a 1-hour confirmation window after grace period expires
 * 3. **Third Transaction**: Finalizes the sale after a block-based delay that depends on `block.number % 256`
 * 
 * **Multi-Transaction Exploitation:**
 * - **Transaction 1**: Owner calls function to initiate sale end, setting timestamp
 * - **Transaction 2**: After 24+ hours, owner confirms sale end within 1-hour window
 * - **Transaction 3**: Owner finalizes sale after block-based delay
 * 
 * **Vulnerability Details:**
 * - Miners can manipulate `block.timestamp` to bypass time restrictions across transactions
 * - The `block.number % 256` creates predictable delays miners can exploit
 * - State variables persist between transactions, allowing accumulated timestamp manipulation
 * - Multiple transaction requirement enables sophisticated timing attacks
 * 
 * **State Variables Required** (to be added to contract):
 * ```solidity
 * uint256 public saleEndTimestamp;
 * bool public saleEndConfirmed;
 * uint256 public saleEndConfirmationTime;
 * ```
 * 
 * **Exploitation Scenarios:**
 * 1. Miners can manipulate timestamps to bypass the 24-hour grace period
 * 2. Miners can extend or shrink the 1-hour confirmation window
 * 3. Block number manipulation affects the final delay calculation
 * 4. Multiple transactions allow accumulated timestamp manipulation effects
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

    // ===== Added variable declarations for sale end logic =====
    uint256 public saleEndTimestamp;
    bool public saleEndConfirmed;
    uint256 public saleEndConfirmationTime;
    // =========================================================
    
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // First call: Set sale end timestamp with 24 hour grace period
        if (saleEndTimestamp == 0) {
            saleEndTimestamp = now + 24 hours;
            emit endOfSale(saleEndTimestamp);
            return;
        }
        
        // Second call: Confirm sale end within grace period
        if (!saleEndConfirmed) {
            require(now >= saleEndTimestamp, "Grace period not yet elapsed");
            require(now <= saleEndTimestamp + 1 hours, "Confirmation window expired");
            saleEndConfirmed = true;
            saleEndConfirmationTime = now;
            return;
        }
        
        // Third call: Finalize sale based on confirmation timestamp
        require(saleEndConfirmed, "Sale end not confirmed");
        require(now >= saleEndConfirmationTime + (block.number % 256) * 10, "Must wait for block-based delay");
        
        require(tokenContract.transfer(owner, tokenContract.balanceOf(this))) ;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        msg.sender.transfer(address(this).balance) ;
    }
}
