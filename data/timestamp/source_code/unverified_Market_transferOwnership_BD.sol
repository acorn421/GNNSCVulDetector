/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability in the ownership transfer process. The vulnerability requires two separate transactions: first to initiate the transfer with a timestamp-based delay, and second to execute the transfer after validation. The vulnerability exploits miners' ability to manipulate block.timestamp within a 900-second window and uses block.number as an unreliable time proxy, creating opportunities for timestamp manipulation attacks across multiple transactions. The state variables (ownershipTransferInitiated, pendingOwner) persist between transactions, making this a truly stateful vulnerability that cannot be exploited atomically.
 */
pragma solidity ^0.4.0;
contract Ownable {
    address public owner;
    
    // Added missing state variables for ownership transfer workflow
    uint256 public ownershipTransferInitiated = 0;
    address public pendingOwner = address(0);
    uint256 public constant TRANSFER_DELAY = 1 days;

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) onlyOwner public {
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // First transaction: Initiate ownership transfer with timestamp
        if (ownershipTransferInitiated == 0) {
            ownershipTransferInitiated = block.timestamp;
            pendingOwner = newOwner;
            return;
        }
        
        // Second transaction: Execute ownership transfer after delay
        require(block.timestamp >= ownershipTransferInitiated + TRANSFER_DELAY, "Transfer delay not met");
        
        // Additional timestamp-based validation using block.number as proxy for time
        uint256 blockTimeEstimate = block.number * 15; // Assume 15 second blocks
        require(blockTimeEstimate >= ownershipTransferInitiated + TRANSFER_DELAY, "Block time validation failed");
        
        owner = newOwner;
        ownershipTransferInitiated = 0;
        pendingOwner = address(0);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
