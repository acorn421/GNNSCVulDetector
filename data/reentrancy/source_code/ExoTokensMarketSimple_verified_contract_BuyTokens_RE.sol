/*
 * ===== SmartInject Injection Details =====
 * Function      : BuyTokens
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding user purchase history tracking and bonus token system. The vulnerability requires multiple function calls to exploit:
 * 
 * 1. **State Variables Added** (assumed to be declared at contract level):
 *    - `mapping(address => uint256) userPurchaseHistory` - tracks cumulative token purchases per user
 *    - `uint256 totalPurchaseVolume` - tracks total contract purchase volume  
 *    - `uint256 bonusThreshold` - threshold for bonus token eligibility
 *    - `uint256 bonusAmount` - bonus token amount awarded
 * 
 * 2. **Multi-Transaction Exploitation Pattern**:
 *    - **Transaction 1**: Attacker calls BuyTokens() with normal ETH amount, receives tokens and gets purchase history recorded
 *    - **Transaction 2+**: Attacker calls BuyTokens() again. During the first ExoToken.transfer() call, if the token contract has callbacks (or attacker controls it), they can reenter BuyTokens()
 *    - **Reentrancy Window**: The external transfer happens before userPurchaseHistory is updated, so the attacker can:
 *      a) Receive tokens from the main call
 *      b) Reenter during transfer callback before state update
 *      c) Their purchase history hasn't been updated yet, so they can manipulate the bonus calculation
 *      d) Potentially claim bonus tokens based on stale state
 * 
 * 3. **Why Multiple Transactions Are Required**:
 *    - The vulnerability exploits accumulated state (userPurchaseHistory) that builds up across transactions
 *    - The bonus system only triggers after reaching a threshold, requiring multiple purchases
 *    - The reentrancy allows manipulation of the purchase history tracking between transactions
 *    - An attacker needs to first establish purchase history, then exploit the reentrancy in subsequent calls
 * 
 * 4. **Realistic Vulnerability Pattern**:
 *    - Purchase history tracking is a common feature in token sale contracts
 *    - Bonus/reward systems based on cumulative purchases are realistic
 *    - The checks-effects-interactions pattern violation is a classic reentrancy vulnerability
 *    - State updates happening after external calls create the exploitation window
 */
pragma solidity ^0.4.25;
// Interface to ERC20 functions used in this contract
interface ERC20token {
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

    // Added variable declarations to fix compilation errors
    mapping(address => uint256) public userPurchaseHistory;
    uint256 public totalPurchaseVolume;
    uint256 public bonusThreshold = 1000 * (10 ** 18); // Example threshold
    uint256 public bonusAmount = 100 * (10 ** 18);     // Example bonus

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
    constructor() public {
        owner = msg.sender;
        weiPerToken = 1000000000000000;
        decimals = 3;
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
        uint256 tokensToXfer = (msg.value/weiPerToken)*(10**18);
        require(exo_balance >= tokensToXfer, "Not enough tokens in contract");
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call before state update - vulnerable to reentrancy
        require(ExoToken.transfer(msg.sender, tokensToXfer), "Couldn't send funds");
        // State update after external call - creates reentrancy window
        userPurchaseHistory[msg.sender] += tokensToXfer;
        totalPurchaseVolume += tokensToXfer;
        // Award bonus tokens based on accumulated purchase history
        if (userPurchaseHistory[msg.sender] >= bonusThreshold) {
            uint256 bonusTokens = (userPurchaseHistory[msg.sender] / bonusThreshold) * bonusAmount;
            if (ExoToken.balanceOf(this) >= bonusTokens) {
                ExoToken.transfer(msg.sender, bonusTokens);
            }
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
