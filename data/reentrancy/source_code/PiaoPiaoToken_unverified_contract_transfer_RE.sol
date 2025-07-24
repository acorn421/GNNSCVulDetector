/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call After State Updates**: Introduced a call to `_to.call()` that occurs AFTER the balance updates but before the Transfer event emission. This creates the classic reentrancy vulnerability pattern.
 * 
 * 2. **Contract Code Check**: Added `_to.code.length > 0` to only call contracts, making the vulnerability conditional on the recipient being a contract.
 * 
 * 3. **Callback Mechanism**: The external call uses `onTokenReceived(address,uint256)` signature, creating a realistic callback pattern that contracts might implement.
 * 
 * 4. **Require Statement**: Added a require statement that enforces the callback success, making the vulnerability more realistic as failed notifications would revert the transaction.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Setup Phase:**
 * - Attacker deploys a malicious contract that implements `onTokenReceived`
 * - Attacker obtains some initial token balance through legitimate means
 * - The malicious contract is now positioned to receive transfers
 * 
 * **Transaction 2 - Initial Exploitation:**
 * - Attacker calls `transfer()` sending tokens to their malicious contract
 * - The function updates balances: `balances[attacker] -= _value` and `balances[maliciousContract] += _value`
 * - The external call `_to.call()` is made to the malicious contract
 * - Inside `onTokenReceived`, the malicious contract can now call `transfer()` again
 * - During reentrancy, the malicious contract sees the updated balance state and can transfer tokens again
 * - This creates a state where tokens can be double-spent across multiple calls
 * 
 * **Transaction 3+ - Continued Exploitation:**
 * - The attacker can continue exploiting the accumulated state inconsistencies
 * - Each subsequent transaction builds upon the state corruption from previous transactions
 * - The vulnerability compounds across multiple transactions as the balance state becomes increasingly inconsistent
 * 
 * **Why Multi-Transaction Requirement is Satisfied:**
 * 
 * 1. **State Accumulation**: Each reentrancy call creates persistent state changes in the `balances` mapping that carry over to subsequent transactions.
 * 
 * 2. **Sequence Dependency**: The vulnerability requires the attacker to first establish a malicious contract recipient, then trigger the transfer to initiate the reentrancy chain.
 * 
 * 3. **Persistent State Corruption**: The balance inconsistencies created during reentrancy persist between transactions, allowing the attacker to exploit these inconsistencies in future transactions.
 * 
 * 4. **Cannot Be Exploited Atomically**: The vulnerability requires the external contract to be deployed and positioned first, then the transfer to be initiated, making it impossible to exploit in a single atomic transaction.
 * 
 * The vulnerability is realistic because many DeFi protocols and token contracts implement similar notification patterns for recipient contracts, making this a genuine security concern in production environments.
 */
pragma solidity ^0.4.24;
contract Ownable {
  address public owner;
  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
  constructor() public {
    owner = msg.sender;
  }

  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    emit OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }
}

contract LoveToken is Ownable{
    uint256 public totalSupply;
    mapping (address => uint256) balances;
    function balanceOf(address _owner) public view returns (uint256 balance);
    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract of incoming transfer
        uint256 size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            // solhint-disable-next-line avoid-call-value
            (bool callSuccess,) = _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
            require(callSuccess, "Transfer notification failed");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(msg.sender, _to, _value);
        return true;
    }
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
}

contract PiaoPiaoToken is LoveToken {
    string public name;                   
    uint8 public decimals;               
    string public symbol;
    string public loveUrl;
    
    constructor() public {
        balances[msg.sender] = 5201314; 
        totalSupply = 5201314;         
        name = "PiaoPiao Token";                   
        decimals = 0;          
        symbol = "PPT";  
    }
    
    function setLoveUrl(string _loveUrl) public onlyOwner returns (bool success) {
        loveUrl = _loveUrl;
        return true;
    }
    
    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }
}
