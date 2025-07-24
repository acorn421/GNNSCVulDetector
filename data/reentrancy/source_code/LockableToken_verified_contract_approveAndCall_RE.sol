/*
 * ===== SmartInject Injection Details =====
 * Function      : approveAndCall
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * This modification introduces a STATEFUL, MULTI-TRANSACTION reentrancy vulnerability by:
 * 
 * 1. **Adding State Tracking**: Introduced `pendingApprovals` and `approvalInProgress` mappings to track approval state across transactions
 * 2. **External Call Before State Updates**: The external call to `receiveApproval` occurs before the actual `approve()` call, creating a window for reentrancy
 * 3. **Multi-Transaction Exploitation Path**: 
 *    - Transaction 1: User calls `approveAndCall`, setting `approvalInProgress[user] = true` and triggering external call
 *    - During external call: Malicious contract can re-enter `approveAndCall` or other token functions while approval is still "in progress"
 *    - Transaction 2+: Subsequent calls can exploit the inconsistent state where `approvalInProgress` is true but actual approval hasn't occurred yet
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - Attacker calls `approveAndCall` with malicious contract address
 * - Malicious contract's `receiveApproval` function re-enters the token contract
 * - During reentrancy, the malicious contract can call `approveAndCall` again or manipulate other functions while `approvalInProgress[attacker] = true`
 * - The vulnerability requires this sequence of calls across multiple transaction contexts to exploit the state inconsistency
 * 
 * **Why Multi-Transaction Required:**
 * - The exploit depends on the persistent state tracking (`pendingApprovals`, `approvalInProgress`) that exists between function calls
 * - The vulnerability window exists only during the external call execution, requiring the malicious contract to initiate new transactions during this window
 * - Single transaction exploitation is prevented by the natural call stack limitations, but multi-transaction reentrancy through callbacks enables state manipulation
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

// Added interface for ApproveAndCallFallBack to fix undeclared identifier error
interface ApproveAndCallFallBack {
    function receiveApproval(address from, uint256 value, address token, bytes data) external;
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => uint256) private pendingApprovals;
    mapping(address => bool) private approvalInProgress;

    function approveAndCall(address _spender, uint256 _value, bytes _data) public payable returns (bool) {
        require(_spender != address(0), "Invalid spender address");
        
        // Store pending approval amount for multi-transaction tracking
        pendingApprovals[msg.sender] = _value;
        approvalInProgress[msg.sender] = true;
        
        // External call before state updates - creates reentrancy opportunity
        // This allows the called contract to re-enter while approval is in progress
        ApproveAndCallFallBack(_spender).receiveApproval(msg.sender, _value, address(this), _data);
        
        // State updates happen after external call - vulnerability window
        // If reentrancy occurs, these updates can be manipulated
        approve(_spender, _value);
        
        // Clear tracking state - but this happens after external call
        approvalInProgress[msg.sender] = false;
        pendingApprovals[msg.sender] = 0;
        
        return true;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
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
