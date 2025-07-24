/*
 * ===== SmartInject Injection Details =====
 * Function      : BuyTokens
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through a time-based bonus system. The vulnerability requires the addition of a state variable 'lastFlashBonusTime' that tracks when flash bonus periods are activated.
 * 
 * **Specific Changes Made:**
 * 1. Added timestamp-dependent bonus logic using block.timestamp
 * 2. Implemented a flash bonus system that gives 3x token multiplier during active periods
 * 3. Created state persistence through lastFlashBonusTime tracking
 * 4. Added cooldown mechanics that span multiple transactions
 * 
 * **Multi-Transaction Exploitation:**
 * The vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Transaction 1 (Setup):** An attacker makes a small purchase to trigger the flash bonus activation when the cooldown period (1 hour) has passed. This sets lastFlashBonusTime to the current block.timestamp.
 * 
 * **Transaction 2 (Exploitation):** Within the same block or shortly after (within miner's timestamp manipulation window of ~900 seconds), the attacker can make a large purchase during the "active" flash bonus period to receive 3x tokens.
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability depends on the persistent state variable lastFlashBonusTime being set in a previous transaction
 * - The bonus system requires the state to be established before it can be exploited
 * - Single transaction exploitation is impossible because the bonus must be "activated" first through state modification
 * - The time-based logic creates windows of opportunity that span multiple blocks/transactions
 * 
 * **Exploitation Mechanism:**
 * 1. Attacker waits for cooldown period to expire (1 hour since last activation)
 * 2. **Transaction 1:** Makes minimal purchase to activate flash bonus (sets lastFlashBonusTime)
 * 3. **Transaction 2:** Immediately makes large purchase within the 10-minute window to get 3x tokens
 * 4. Miner timestamp manipulation can extend the bonus window or trigger it prematurely across transactions
 * 
 * **Realistic Vulnerability Pattern:**
 * This mimics real-world DeFi protocols that implement time-based bonuses, flash sales, or dynamic pricing mechanisms that rely on block.timestamp for critical business logic without proper validation.
 */
pragma solidity ^0.4.25;
// Interface to ERC20 functions used in this contract
interface ERC20token {
    //function balanceOf(address who) external view returns (uint256);
    //function balanceOf(address _owner) constant returns (uint256 balance) {}
    function balanceOf(address who) constant returns (uint);
    function transfer(address to, uint256 value) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}
contract ExoTokensMarketSimple {
    ERC20token ExoToken;
    address owner;
    uint256 weiPerToken;
    uint8 decimals;
    
    // Added state variable to fix compilation errors
    uint256 public lastFlashBonusTime;

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
    constructor() public {
        owner = msg.sender;
        weiPerToken = 1000000000000000;
        decimals = 3;
        lastFlashBonusTime = 0; // initialize to 0
    }

    function setWeiPerToken(uint256 _weiPerToken) public onlyOwner {
        weiPerToken = _weiPerToken;
    }
    function getWeiPerToken() public view returns(uint256) {
        return weiPerToken;
    }
    function setERC20Token(address tokenAddr) public onlyOwner  {
        ExoToken = ERC20token(tokenAddr);
    }
    function getERC20Token() public view returns(address) {
        return ExoToken;
    }
    function getERC20Balance() public view returns(uint256) {
        return ExoToken.balanceOf(this);
    }
    function depositERC20Token(uint256 _exo_amount) public  {
        require(ExoToken.allowance(msg.sender, this) >= _exo_amount);
        require(ExoToken.transferFrom(msg.sender, this, _exo_amount));
    }

    // ERC20(GUP) buying function
    // All of the ETH included in the TX is converted to GUP
    function BuyTokens() public payable{
        require(msg.value > 0, "eth value must be non zero");
        uint256 exo_balance = ExoToken.balanceOf(this);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based bonus system - vulnerability injection
        uint256 currentTime = block.timestamp;
        uint256 bonusMultiplier = 1;
        
        // Check if flash bonus period is active (lasts 10 minutes)
        if (currentTime >= lastFlashBonusTime && currentTime <= lastFlashBonusTime + 600) {
            bonusMultiplier = 3; // 3x token bonus during flash period
        }
        
        // Activate new flash bonus if enough time has passed (1 hour cooldown)
        if (currentTime >= lastFlashBonusTime + 3600) {
            lastFlashBonusTime = currentTime;
            bonusMultiplier = 3; // Immediate activation
        }
        
        uint256 tokensToXfer = (msg.value/weiPerToken)*(10**18)*bonusMultiplier;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        require(exo_balance >= tokensToXfer, "Not enough tokens in contract");
        require(ExoToken.transfer(msg.sender, tokensToXfer), "Couldn't send funds");
    }

    // Withdraw erc20 tokens
    function withdrawERC20Tokens(uint _val) public onlyOwner {
        require(ExoToken.transfer(msg.sender, _val), "Couldn't send funds"); // send EXO tokens
    }

    // Withdraw Ether
    function withdrawEther() public onlyOwner {
        msg.sender.transfer(address(this).balance);

    }
 
    // change the owner
    function setOwner(address _owner) public onlyOwner {
        owner = _owner;    
    }
    // fallback
    function() external payable { }   
}
