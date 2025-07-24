/*
 * ===== SmartInject Injection Details =====
 * Function      : transferAndCall
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Tracking**: Introduced `pendingTransfers` and `processingCallback` mappings to track transfer state across transactions
 * 2. **External Call Before State Updates**: Moved the external callback to occur before balance updates, creating a reentrancy window
 * 3. **State-Dependent Execution**: Made the transfer completion dependent on accumulated state from previous transactions
 * 4. **Multi-Transaction Exploitation Path**: The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: Attacker calls `transferAndCall` with a malicious recipient contract that sets up attack state during the callback but doesn't immediately exploit (due to state dependencies)
 * - **Transaction 2**: Attacker calls `transferAndCall` again, and the malicious recipient now exploits the accumulated state from Transaction 1, potentially manipulating `pendingTransfers` or `processingCallback` states
 * - **Transaction 3+**: Further calls can drain tokens by exploiting the persistent state inconsistencies
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability depends on `pendingTransfers` and `processingCallback` state persistence between calls
 * - Single transaction reentrancy is limited by the state validation checks
 * - Attacker needs to accumulate state across multiple transactions to bypass the conditional checks
 * - The external call creates a reentrancy window, but effective exploitation requires pre-established state from previous transactions
 * 
 * This creates a realistic scenario where an attacker must perform multiple transactions to first establish the necessary state conditions, then exploit them in subsequent transactions.
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
    mapping(address => uint256) internal balances; // Added mapping for balances
    function totalSupply() public view returns (uint256);
    function balanceOf(address who) public view returns (uint256);
    function transfer(address to, uint256 value) public returns (bool);
    event Transfer(address indexed from, address indexed to, uint256 value);
    function allowance(address owner, address spender) public view returns (uint256);
    function transferFrom(address from, address to, uint256 value) public returns (bool);
    function approve(address spender, uint256 value) public returns (bool);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    function approveAndCall(address _spender, uint256 _value, bytes _data) public payable returns (bool);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => uint256) private pendingTransfers;
    mapping(address => bool) private processingCallback;

    function transferAndCall(address _to, uint256 _value, bytes _data) public payable returns (bool) {
        require(_to != address(0), "Invalid recipient");
        require(_value > 0, "Value must be positive");
        require(balanceOf(msg.sender) >= _value, "Insufficient balance");
        
        // Store pending transfer amount for callback validation
        pendingTransfers[msg.sender] = _value;
        
        // Mark that we're processing a callback to allow state inspection
        processingCallback[msg.sender] = true;
        
        // Make external call to recipient contract BEFORE updating balances
        // This creates reentrancy opportunity during callback processing
        if (isContract(_to)) {
            (bool success,) = _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256,bytes)", msg.sender, _value, _data));
            require(success, "Callback failed");
        }
        
        // State updates happen after external call - vulnerable to reentrancy
        // But exploitation requires multiple transactions due to pendingTransfers dependency
        if (pendingTransfers[msg.sender] == _value && processingCallback[msg.sender]) {
            // Perform the actual transfer
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            
            // Clear pending state only after successful transfer
            pendingTransfers[msg.sender] = 0;
            processingCallback[msg.sender] = false;
            
            emit Transfer(msg.sender, _to, _value);
            return true;
        }
        
        return false;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
    function transferFromAndCall(address _from, address _to, uint256 _value, bytes _data) public payable returns (bool);

    // Helper function to check if address is a contract in Solidity ^0.4.0
    function isContract(address _addr) private view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }
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
