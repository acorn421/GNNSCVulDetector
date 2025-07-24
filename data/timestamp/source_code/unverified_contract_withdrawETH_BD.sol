/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawETH
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by implementing a withdrawal cooldown system with time-based withdrawal limits. The vulnerability requires multiple transactions over time to exploit and relies on block.timestamp for critical security logic.
 * 
 * **Key Changes Made:**
 * 1. Added state dependency on `lastWithdrawalTime` and `withdrawalCooldown` variables (assumed to be contract state variables)
 * 2. Implemented time-based withdrawal limits that vary based on elapsed time since last withdrawal
 * 3. Used block.timestamp for critical access control and withdrawal amount calculations
 * 4. Created a cooldown mechanism that can be manipulated through timestamp dependency
 * 
 * **Multi-Transaction Exploitation:**
 * The vulnerability can be exploited across multiple transactions as follows:
 * 
 * **Transaction 1 (Initial Setup):**
 * - Owner calls withdrawETH() for the first time
 * - Sets lastWithdrawalTime = block.timestamp
 * - Limited to 10% withdrawal due to timeElapsed < 1 day initially
 * - Establishes baseline timestamp state
 * 
 * **Transaction 2 (Timestamp Manipulation):**
 * - Miner or attacker with timestamp manipulation capability advances block.timestamp
 * - Owner calls withdrawETH() again after manipulated timestamp shows >= 1 week elapsed
 * - System incorrectly calculates timeElapsed as >= 1 week due to manipulated timestamp
 * - Allows full balance withdrawal bypassing intended time-based limits
 * 
 * **Transaction 3 (Repeated Exploitation):**
 * - Can repeat the process by manipulating timestamps to reset cooldown periods
 * - Each transaction builds on the state from previous transactions
 * - Vulnerability compounds over multiple withdrawal attempts
 * 
 * **Why Multiple Transactions Are Required:**
 * 1. **State Accumulation**: The vulnerability requires establishing initial timestamp state in the first transaction
 * 2. **Time-Based Logic**: The withdrawal limits are calculated based on elapsed time between transactions
 * 3. **Cooldown Reset**: Each transaction modifies the cooldown state affecting future transactions
 * 4. **Exploitation Window**: Single transaction cannot manipulate both the initial state and exploit the time calculation
 * 5. **Progressive Bypass**: The time-based limits require multiple calls to progressively bypass restrictions
 * 
 * The vulnerability is realistic as it implements common financial security patterns (cooldowns, time-based limits) but relies on the unreliable block.timestamp for critical security decisions, making it exploitable by miners or in environments where timestamp manipulation is possible.
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
    
    uint256 public lastWithdrawalTime;
    uint256 public withdrawalCooldown;

    constructor(IERC20Token _tokenContract, uint256 LUPXperETH) public {
        owner = msg.sender ;
        tokenContract = _tokenContract ;
        LUPXPrice = LUPXperETH ; 
        lastWithdrawalTime = 0;
        withdrawalCooldown = 0;
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Emergency withdrawal cooldown - prevent rapid successive withdrawals
        if (lastWithdrawalTime == 0) {
            lastWithdrawalTime = block.timestamp;
        } else {
            require(block.timestamp >= lastWithdrawalTime + withdrawalCooldown, "Withdrawal cooldown period not met");
        }
        
        // Calculate withdrawal amount based on time elapsed since last withdrawal
        uint256 timeElapsed = block.timestamp - lastWithdrawalTime;
        uint256 maxWithdrawal = address(this).balance;
        
        // Time-based withdrawal limit: allow more withdrawal for longer waiting periods
        if (timeElapsed < 1 days) {
            maxWithdrawal = address(this).balance / 10; // 10% limit for frequent withdrawals
        } else if (timeElapsed < 1 weeks) {
            maxWithdrawal = address(this).balance / 2;  // 50% limit for weekly withdrawals
        }
        // Full withdrawal allowed after 1 week
        
        lastWithdrawalTime = block.timestamp;
        withdrawalCooldown = 1 hours; // Reset cooldown to 1 hour
        
        msg.sender.transfer(maxWithdrawal);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }

    function endLUPXSale() public onlyOwner { 
        require(tokenContract.transfer(owner, tokenContract.balanceOf(this))) ;
        msg.sender.transfer(address(this).balance) ;
        emit endOfSale(now) ; 
    }
}
