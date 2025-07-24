/*
 * ===== SmartInject Injection Details =====
 * Function      : enableTimedSale
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence through timed sales functionality. The vulnerability is stateful and multi-transaction: 1) Owner calls enableTimedSale() to set sale parameters with timestamps, 2) State persists between transactions with saleStartTime/saleEndTime, 3) Users call buyTokensWithDiscount() which depends on block.timestamp (now). Miners can manipulate timestamps within bounds to either extend sales or make them start earlier/later than intended, potentially allowing discounted purchases outside intended timeframes or preventing legitimate purchases.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    uint256 public saleStartTime;
    uint256 public saleEndTime;
    uint256 public discountedWeiPerToken;
    bool public timedSaleActive;

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
    
    function enableTimedSale(uint256 _durationInSeconds, uint256 _discountedWeiPerToken) public onlyOwner {
        saleStartTime = now;
        saleEndTime = now + _durationInSeconds;
        discountedWeiPerToken = _discountedWeiPerToken;
        timedSaleActive = true;
    }

    function disableTimedSale() public onlyOwner {
        timedSaleActive = false;
    }

    function buyTokensWithDiscount() public payable {
        require(msg.value > 0, "eth value must be non zero");
        require(timedSaleActive, "Timed sale is not active");
        require(now >= saleStartTime, "Sale has not started yet");
        require(now <= saleEndTime, "Sale has ended");

        uint256 exo_balance = ExoToken.balanceOf(this);
        uint256 tokensToXfer = (msg.value/discountedWeiPerToken)*(10**18);
        require(exo_balance >= tokensToXfer, "Not enough tokens in contract");
        require(ExoToken.transfer(msg.sender, tokensToXfer), "Couldn't send funds");
    }
    // === END FALLBACK INJECTION ===

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