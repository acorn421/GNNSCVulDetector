/*
 * ===== SmartInject Injection Details =====
 * Function      : initiateWithdrawal
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * This injection creates a stateful, multi-transaction reentrancy vulnerability through a withdrawal system. The vulnerability requires: 1) First transaction: User calls initiateWithdrawal() to set up withdrawal request with state variables. 2) Wait for delay period to pass. 3) Second transaction: User calls executeWithdrawal() where the reentrancy occurs. The vulnerability exists because the external token transfer happens before state variables are reset, allowing an attacker to re-enter and drain tokens by calling executeWithdrawal() multiple times in the same transaction through a malicious token contract.
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

    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    mapping(address => uint256) public pendingWithdrawals;
    mapping(address => bool) public withdrawalRequested;
    uint256 public withdrawalDelay = 24 hours;
    mapping(address => uint256) public withdrawalRequestTime;
    
    // Initiate a withdrawal request - First transaction
    function initiateWithdrawal(uint256 _amount) public {
        require(_amount > 0, "Amount must be greater than 0");
        require(ExoToken.balanceOf(msg.sender) >= _amount, "Insufficient token balance");
        
        // Set withdrawal request
        withdrawalRequested[msg.sender] = true;
        pendingWithdrawals[msg.sender] = _amount;
        withdrawalRequestTime[msg.sender] = now;
    }
    
    // Execute withdrawal after delay - Second transaction (vulnerable to reentrancy)
    function executeWithdrawal() public {
        require(withdrawalRequested[msg.sender], "No withdrawal request found");
        require(now >= withdrawalRequestTime[msg.sender] + withdrawalDelay, "Withdrawal delay not met");
        require(pendingWithdrawals[msg.sender] > 0, "No pending withdrawal amount");
        
        uint256 amount = pendingWithdrawals[msg.sender];
        require(ExoToken.balanceOf(this) >= amount, "Insufficient contract balance");
        
        // Vulnerable: External call before state update
        require(ExoToken.transfer(msg.sender, amount), "Transfer failed");
        
        // State updates after external call - vulnerable to reentrancy
        pendingWithdrawals[msg.sender] = 0;
        withdrawalRequested[msg.sender] = false;
        withdrawalRequestTime[msg.sender] = 0;
    }
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
