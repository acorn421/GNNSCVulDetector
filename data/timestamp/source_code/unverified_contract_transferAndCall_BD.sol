/*
 * ===== SmartInject Injection Details =====
 * Function      : transferAndCall
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through time-based rate limiting that relies on block.timestamp for critical security decisions. The vulnerability requires multiple transactions to exploit because:
 * 
 * 1. **State Accumulation**: The transferAccumulator mapping tracks cumulative transfers over time, requiring multiple transactions to build up exploitable state.
 * 
 * 2. **Timestamp Manipulation Sequence**: 
 *    - Transaction 1: Attacker makes initial transfer, establishes lastTransferTime
 *    - Transaction 2+: Miner manipulates block.timestamp to bypass cooldown and reset accumulator
 *    - Multiple transactions: Attacker exceeds intended limits through timestamp manipulation
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - Normal user makes legitimate transfers, building up accumulator state
 *    - Miner collaborates to manipulate timestamps across multiple blocks
 *    - Attacker can bypass both cooldown and hourly limits through sequential timestamp manipulation
 *    - Each transaction depends on state from previous transactions
 * 
 * 4. **Vulnerability Mechanics**:
 *    - Uses block.timestamp for critical access control (cooldown enforcement)
 *    - Stores timestamp in state for future reference (lastTransferTime)
 *    - Implements time-based calculations for rate limiting (hourly reset)
 *    - Accumulates state across transactions that can be manipulated
 * 
 * The vulnerability cannot be exploited in a single transaction because it requires the establishment of previous state (lastTransferTime) and the manipulation of block.timestamp across multiple blocks to bypass the intended security restrictions.
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
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
// State variables to add to the contract
mapping(address => uint256) private lastTransferTime;
mapping(address => uint256) private transferAccumulator;
uint256 private constant TRANSFER_COOLDOWN = 300; // 5 minutes in seconds
uint256 private constant MAX_HOURLY_TRANSFERS = 1000;

function transferAndCall(address _to, uint256 _value, bytes _data) public payable returns (bool) {
    // Store block timestamp for rate limiting (vulnerable to manipulation)
    uint256 currentTime = block.timestamp;
    
    // Check if enough time has passed since last transfer
    require(currentTime >= lastTransferTime[msg.sender] + TRANSFER_COOLDOWN, "Transfer cooldown not met");
    
    // Reset accumulator if an hour has passed (vulnerable calculation)
    if (currentTime - lastTransferTime[msg.sender] >= 3600) {
        transferAccumulator[msg.sender] = 0;
    }
    
    // Add current transfer to accumulator
    transferAccumulator[msg.sender] += _value;
    
    // Check hourly limit using accumulated transfers
    require(transferAccumulator[msg.sender] <= MAX_HOURLY_TRANSFERS, "Hourly transfer limit exceeded");
    
    // Update last transfer time (vulnerable to timestamp manipulation)
    lastTransferTime[msg.sender] = currentTime;
    
    // Perform the actual transfer and call
    require(transfer(_to, _value), "Transfer failed");
    
    // Call the target contract if data is provided
    if (_data.length > 0) {
        require(_to.call(_data), "External call failed");
    }
    
    return true;
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
}
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