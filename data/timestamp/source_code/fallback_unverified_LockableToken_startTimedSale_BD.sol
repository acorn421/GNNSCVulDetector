/*
 * ===== SmartInject Injection Details =====
 * Function      : startTimedSale
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This function creates a timestamp dependence vulnerability that is stateful and requires multiple transactions to exploit. A malicious miner can manipulate the timestamp when calling this function to set a favorable sale end time, then later manipulate timestamps during the sale period to extend or shorten the sale duration. The vulnerability requires: 1) First transaction to start the sale with manipulated timestamp, 2) Second transaction to exploit the manipulated timeframe during token purchases. The state (saleEndTime, timedSaleActive) persists between transactions, making this a multi-transaction vulnerability.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    uint256 public saleEndTime;
    uint256 public bonusMultiplier = 1;
    bool public timedSaleActive = false;

    function startTimedSale(uint256 _durationInSeconds, uint256 _bonusMultiplier) onlyOwner public {
        require(_durationInSeconds > 0, "Duration must be positive");
        require(_bonusMultiplier > 0, "Bonus multiplier must be positive");
        saleEndTime = now + _durationInSeconds;
        bonusMultiplier = _bonusMultiplier;
        timedSaleActive = true;
    }
    // === END FALLBACK INJECTION ===

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
    
    function withdrawToken() onlyOwner public  {
        token.transfer(owner, tokenBalance());
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
