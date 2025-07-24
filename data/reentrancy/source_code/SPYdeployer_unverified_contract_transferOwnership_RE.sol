/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
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
 * Injected a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the new owner before updating the owner state. This creates a classic reentrancy pattern where:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call `_newOwner.call(abi.encodeWithSignature("onOwnershipTransferred(address)", owner))` before the state update
 * 2. Added a contract existence check `_newOwner.code.length > 0` to make the call realistic
 * 3. Added error handling with `require(success, "New owner notification failed")` to maintain function integrity
 * 4. Moved the critical state update `owner = _newOwner` to after the external call
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * The vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Transaction 1 (Setup):** 
 * - Current owner calls `transferOwnership(maliciousContract)`
 * - The malicious contract's `onOwnershipTransferred` callback is triggered
 * - During this callback, `owner` is still the old owner (state not yet updated)
 * - The malicious contract can call other owner-only functions like `withdrawAll()` or `withdrawERC20()` while still appearing as the legitimate owner
 * 
 * **Transaction 2 (Exploitation):**
 * - The malicious contract's callback can also call `transferOwnership()` again to a different address
 * - This creates a chain of ownership transfers that can be exploited
 * - Each subsequent call happens before the previous ownership transfer completes
 * 
 * **Why Multiple Transactions Are Required:**
 * 1. **State Persistence:** The `owner` variable persists between transactions, and the vulnerability exploits the window where external calls occur before state updates
 * 2. **Accumulated Effects:** Each reentrancy call can trigger additional state changes (like fund withdrawals) that accumulate across the attack sequence
 * 3. **Chain Exploitation:** The attack involves setting up the malicious contract in one transaction, then triggering the vulnerable ownership transfer in subsequent transactions
 * 4. **Cross-Function Impact:** The reentrancy allows calling other owner-only functions during the ownership transfer process, requiring multiple function calls across transactions
 * 
 * This creates a realistic vulnerability where an attacker needs to deploy a malicious contract, then initiate the ownership transfer process, making it inherently multi-transaction and stateful.
 */
pragma solidity ^0.4.24;

contract ERC20 {
  uint256 public totalSupply;

  function balanceOf(address who) public view returns (uint256);
  function transfer(address to, uint256 value) public returns (bool);
  function allowance(address owner, address spender) public view returns (uint256);
  function transferFrom(address from, address to, uint256 value) public returns (bool);
  function approve(address spender, uint256 value) public returns (bool);

  event Approval(address indexed owner, address indexed spender, uint256 value);
  event Transfer(address indexed from, address indexed to, uint256 value);
}

contract SPYdeployer {

    address public owner;
     string public  name;
    event OwnershipTransferred(address indexed _from, address indexed _to);
    
    constructor() public {
        
        owner = address(0x6968a3cDc11f71a85CDd13BB2792899E5D215DbB); // The reserves wallet address
        
    }
    
    modifier onlyOwner {
        require(msg.sender == owner, "You are not the owner");
        _;
    }

    
    
    // transfer Ownership to other address
    function transferOwnership(address _newOwner) public onlyOwner {
        require(_newOwner != address(0x0));
        emit OwnershipTransferred(owner,_newOwner);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify the new owner about ownership transfer
        // This external call happens before state update, creating reentrancy vulnerability
        if (isContract(_newOwner)) {
            (bool success,) = _newOwner.call(abi.encodeWithSignature("onOwnershipTransferred(address)", owner));
            require(success, "New owner notification failed");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        owner = _newOwner;
    }
    

    // keep all tokens sent to this address
    function() payable public {
        emit Received(msg.sender, msg.value);
    }

    // callable by owner only, after specified time
    function withdrawAll() onlyOwner public {
       // withdraw balance
       msg.sender.transfer(address(this).balance);
       emit Withdrew(msg.sender, address(this).balance);
    }

    // callable by owner only, after specified time, only for Tokens implementing ERC20
    function withdrawERC20(address _tokenContract) onlyOwner public {
       ERC20 token = ERC20(_tokenContract);
       uint256 tokenBalance = token.balanceOf(this);
       token.transfer(owner, tokenBalance);
       emit WithdrewTokens(_tokenContract, msg.sender, tokenBalance);
    }

    // callable by owner only, after specified time, only for Tokens implementing ERC20
    function withdrawERC20Amount(address _tokenContract, uint256 _amount) onlyOwner public {
       ERC20 token = ERC20(_tokenContract);
       uint256 tokenBalance = token.balanceOf(this);
       require(tokenBalance >= _amount, "Not enough funds in the reserve");
       token.transfer(owner, _amount);
       emit WithdrewTokens(_tokenContract, msg.sender, _amount);
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }

    event Received(address from, uint256 amount);
    event Withdrew(address to, uint256 amount);
    event WithdrewTokens(address tokenContract, address to, uint256 amount);
}
