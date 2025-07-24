/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleTokenRelease
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue where the contract relies on 'now' (block.timestamp) for time-locked token releases. The vulnerability is stateful and multi-transaction because: 1) First transaction: Owner calls scheduleTokenRelease() to set up a time-locked release, storing the amount and timestamp in contract state. 2) Second transaction: User calls releaseScheduledTokens() when they believe the time has passed. 3) The vulnerability can be exploited by miners who can manipulate block timestamps within reasonable bounds to either delay or accelerate token releases. The state persists between transactions through the scheduledReleases and releaseTimestamps mappings.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // State variables for time-locked token releases
    mapping(address => uint256) public scheduledReleases;
    mapping(address => uint256) public releaseTimestamps;
    // === END FALLBACK INJECTION ===

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
    constructor() public {
        owner = msg.sender;
        weiPerToken = 1000000000000000;
        decimals = 3;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Schedule tokens for time-locked release
    function scheduleTokenRelease(uint256 _amount, uint256 _releaseTime) public onlyOwner {
        require(_amount > 0, "Amount must be greater than 0");
        require(_releaseTime > now, "Release time must be in the future");
        require(ExoToken.balanceOf(this) >= _amount, "Not enough tokens in contract");
        scheduledReleases[msg.sender] = _amount;
        releaseTimestamps[msg.sender] = _releaseTime;
    }
    // Release scheduled tokens (vulnerable to timestamp manipulation)
    function releaseScheduledTokens() public {
        require(scheduledReleases[msg.sender] > 0, "No tokens scheduled for release");
        require(now >= releaseTimestamps[msg.sender], "Release time not yet reached");
        uint256 tokensToRelease = scheduledReleases[msg.sender];
        scheduledReleases[msg.sender] = 0;
        releaseTimestamps[msg.sender] = 0;
        require(ExoToken.transfer(msg.sender, tokensToRelease), "Token transfer failed");
    }
    // Update release time (additional vulnerability point)
    function updateReleaseTime(uint256 _newReleaseTime) public onlyOwner {
        require(scheduledReleases[msg.sender] > 0, "No scheduled release found");
        require(_newReleaseTime > now, "New release time must be in the future");
        releaseTimestamps[msg.sender] = _newReleaseTime;
    }
    // === END FALLBACK INJECTION ===

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
