/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawRewards
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This introduces a stateful, multi-transaction reentrancy vulnerability. The attack requires: 1) First transaction to call claimRewards() to accumulate pendingRewards state, 2) Second transaction to call withdrawRewards() which makes an external call before updating state, allowing reentrancy to drain funds. The vulnerability is stateful as it depends on the pendingRewards mapping persisting between transactions, and multi-transaction as it requires separate calls to claim and withdraw rewards.
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
    event rewardClaimed(address claimer, uint256 amount);
    event rewardWithdrawn(address withdrawer, uint256 amount);

    mapping(address => uint256) public pendingRewards;
    mapping(address => bool) public rewardWithdrawing;
    
    constructor(IERC20Token _tokenContract, uint256 LUPXperETH) public {
        owner = msg.sender ;
        tokenContract = _tokenContract ;
        LUPXPrice = LUPXperETH ; 
    }

    function claimRewards() public {
        uint256 reward = tokensSold * msg.value / 1000; // 0.1% of tokens sold as reward
        pendingRewards[msg.sender] += reward;
        emit rewardClaimed(msg.sender, reward);
    }

    function withdrawRewards() public {
        require(!rewardWithdrawing[msg.sender], "Withdrawal in progress");
        require(pendingRewards[msg.sender] > 0, "No rewards to withdraw");
        
        rewardWithdrawing[msg.sender] = true;
        
        uint256 reward = pendingRewards[msg.sender];
        
        // External call before state update - reentrancy vulnerability
        if (msg.sender.call.value(reward)()) {
            pendingRewards[msg.sender] = 0; // State update after external call
            rewardWithdrawing[msg.sender] = false;
            emit rewardWithdrawn(msg.sender, reward);
        } else {
            rewardWithdrawing[msg.sender] = false;
            revert("Transfer failed");
        }
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
