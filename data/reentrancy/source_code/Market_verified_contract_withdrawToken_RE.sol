/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawToken
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 1. Added state variables: totalWithdrawn mapping, maxWithdrawalAmount, and withdrawing flag
 * 2. Implemented withdrawal limits with state tracking that persists across transactions
 * 3. State update (totalWithdrawn[owner] += toWithdraw) occurs before external call
 * 4. External token.transfer() call can trigger reentrancy if token contract has callbacks
 * 5. The vulnerability requires multiple transactions: initial setup/state accumulation, then exploitation during callback
 * 6. Attacker can manipulate totalWithdrawn state through reentrancy during token transfer callbacks
 * 7. Multi-transaction nature: requires state buildup over multiple calls to maximize exploitation impact
 */
pragma solidity ^0.4.0;
contract Ownable {
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
}
contract LockableToken is Ownable {
    function totalSupply() public view returns (uint256);
    function balanceOf(address who) public view returns (uint256);
    function transfer(address to, uint256 value) public returns (bool);
    event Transfer(address indexed from, address indexed to, uint256 value);
    function allowance(address owner, address spender) public view returns (uint256);
    function transferFrom(address from, address to, uint256 value) public returns (bool);
    function approve(address spender, uint256 value) public returns (bool);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    function approveAndCall(address _spender, uint256 _value, bytes _data) public payable returns (bool);
    function transferAndCall(address _to, uint256 _value, bytes _data) public payable returns (bool);
    function transferFromAndCall(address _from, address _to, uint256 _value, bytes _data) public payable returns (bool);
}

contract Market is Ownable{
    LockableToken private token;
    string public Detail;
    uint256 public SellAmount = 0;
    uint256 public WeiRatio = 0;

    event TokenAddressChange(address token);
    event Buy(address sender,uint256 rate,uint256 value,uint256 amount);

    function () payable public {
        buyTokens(msg.sender);
    }
    
    function tokenDetail(string memory _detail) onlyOwner public {
        Detail = _detail;
    }
    
    function tokenPrice(uint256 _price) onlyOwner public {
        WeiRatio = _price;
    }

    function tokenAddress(address _token) onlyOwner public {
        require(_token != address(0), "Token address cannot be null-address");
        token = LockableToken(_token);
        emit TokenAddressChange(_token);
    }

    function tokenBalance() public view returns (uint256) {
        return token.balanceOf(address(this));
    }

    function withdrawEther() onlyOwner public  {
        require(address(this).balance > 0, "Not have Ether for withdraw");
        owner.transfer(address(this).balance);
    }
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint256) public totalWithdrawn;
    uint256 public maxWithdrawalAmount = 1000000 * 10**18; // 1M tokens max
    bool private withdrawing;

    function withdrawToken() onlyOwner public {
        require(!withdrawing, "Withdrawal in progress");
        withdrawing = true;
        
        uint256 balance = tokenBalance();
        uint256 allowedWithdrawal = maxWithdrawalAmount - totalWithdrawn[owner];
        uint256 toWithdraw = balance > allowedWithdrawal ? allowedWithdrawal : balance;
        
        require(toWithdraw > 0, "No tokens available for withdrawal");
        
        // Update state before external call - vulnerability point
        totalWithdrawn[owner] += toWithdraw;
        
        // External call that can trigger reentrancy
        token.transfer(owner, toWithdraw);
        
        withdrawing = false;
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function buyTokens(address _buyer) private {
        require(_buyer != 0x0);
        require(msg.value > 0);

        uint256 tokens = msg.value * WeiRatio;
        require(tokenBalance() >= tokens, "Not enough tokens for sale");
        token.transfer(_buyer, tokens);
        SellAmount += tokens;

        emit Buy(msg.sender,WeiRatio,msg.value,tokens);
    }
}