/*
 * ===== SmartInject Injection Details =====
 * Function      : distributeToken
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to recipient contracts after state updates. This creates a classic reentrancy scenario where:
 * 
 * 1. **State Changes First**: The balanceOf mappings are updated before the external call
 * 2. **External Call Window**: The call to addresses[i].call() creates a reentrancy opportunity
 * 3. **Multi-Transaction Exploitation**: 
 *    - Transaction 1: Malicious contract is included in addresses[] array and receives tokens
 *    - Transaction 2: During the callback, the malicious contract calls distributeToken again
 *    - The reentrancy occurs because the loop hasn't completed from the first call, allowing state manipulation
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Setup Phase (Transaction 1)**: Owner calls distributeToken including malicious contract address
 * - **Reentrancy Phase (Transaction 2)**: During callback, malicious contract re-enters distributeToken before original call completes
 * - **Exploitation**: The malicious contract can manipulate the distribution process by calling distributeToken recursively
 * 
 * **Why Multi-Transaction Required:**
 * - The malicious contract must first be a recipient to receive the callback
 * - Only during the callback can it re-enter the function
 * - The vulnerability depends on the accumulated state from the first transaction
 * - Single-transaction exploitation is not possible because the contract needs to be established as a recipient first
 * 
 * This pattern is realistic as many token contracts implement recipient notifications for compliance or user experience purposes.
 */
pragma solidity ^0.4.8;

/**
 * Math operations with safety checks
 */
contract SafeMath {
  function safeMul(uint256 a, uint256 b) internal returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function safeDiv(uint256 a, uint256 b) internal returns (uint256) {
    assert(b > 0);
    uint256 c = a / b;
    assert(a == b * c + a % b);
    return c;
  }

  function safeSub(uint256 a, uint256 b) internal returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function safeAdd(uint256 a, uint256 b) internal returns (uint256) {
    uint256 c = a + b;
    assert(c>=a && c>=b);
    return c;
  }

  function assert(bool assertion) internal {
    if (!assertion) {
      throw;
    }
  }
}
contract BITXOXO is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    address public owner;
    // uint256 public myBalance = this.balance;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function BITXOXO() public {
        balanceOf[msg.sender] = 20000000000000000000000000;              // Give the creator all initial tokens
        totalSupply = 20000000000000000000000000;                        // Update total supply
        name = "BITXOXO";                                   // Set the name for display purposes
        symbol = "XOXO";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
        owner = msg.sender;
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        if (_to == 0x0) throw;                               // Prevent transfer to 0x0 address. Use burn() instead
		if (_value <= 0) throw; 
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                     // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
        public returns (bool success) {
		if (_value <= 0) throw; 
        allowance[msg.sender][_spender] = _value;
        return true;
    }
       

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (_to == 0x0) throw;                                // Prevent transfer to 0x0 address. Use burn() instead
		if (_value <= 0) throw; 
        if (balanceOf[_from] < _value) throw;                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw;  // Check for overflows
        if (_value > allowance[_from][msg.sender]) throw;     // Check allowance
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                           // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        Transfer(_from, _to, _value);
        return true;
    }

  
	 
    function distributeToken(address[] addresses, uint256[] _value) public onlyCreator {
     for (uint i = 0; i < addresses.length; i++) {
         balanceOf[msg.sender] -= _value[i];
         balanceOf[addresses[i]] += _value[i];
         Transfer(msg.sender, addresses[i], _value[i]);
         // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
         
         // Add callback mechanism for recipient notification
         if (extcodesize(addresses[i]) > 0) {
             // External call to recipient contract after state update
             addresses[i].call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value[i]);
         }
         // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        }
    }

    // Helper for address.code.length in 0.4.x
    function extcodesize(address _addr) internal view returns (uint256 size) {
        assembly { size := extcodesize(_addr) }
    }

modifier onlyCreator() {
        require(msg.sender == owner);   
        _;
    }
	
	// transfer balance to owner
    function withdrawEther(uint256 amount) public {
		if(msg.sender != owner)throw;
		owner.transfer(amount);
    }
	
	// can accept ether
	function() public payable {
    }

    function transferOwnership(address newOwner) public onlyCreator {
        require(newOwner != address(0));
        uint256 _leftOverTokens = balanceOf[msg.sender];
        balanceOf[newOwner] = SafeMath.safeAdd(balanceOf[newOwner], _leftOverTokens);                            // Add the same to the recipient
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _leftOverTokens);                     // Subtract from the sender
        Transfer(msg.sender, newOwner, _leftOverTokens);     
        owner = newOwner;
    }

}
