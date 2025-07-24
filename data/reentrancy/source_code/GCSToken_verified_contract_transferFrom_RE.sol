/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback to the recipient address after balance updates but before allowance decrements. This creates a critical window where the recipient can re-enter the function with updated balances but unchanged allowances, enabling accumulated exploitation across multiple transactions. The vulnerability requires: 1) Initial transaction to set up allowances, 2) Malicious contract deployment at recipient address, 3) Exploitation transaction triggering the callback, 4) Potential additional transactions to maximize the exploit through allowance manipulation.
 */
pragma solidity ^0.4.8;
contract Ownable {
  address public owner;
  

  function Ownable() {
    owner = msg.sender;
  }

  modifier onlyOwner() {
    if (msg.sender != owner) {
      throw;
    }
    _;
  }

  function transferOwnership(address newOwner) onlyOwner {
    if (newOwner != address(0)) {
      owner = newOwner;
    }
  }
  
  function kill() onlyOwner {
     selfdestruct(owner);
  }
}
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract GCSToken is Ownable{
    /* Public variables of the token */
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    function () {
        throw;
    }
    /* Initializes contract with initial supply tokens to the creator of the contract */
    function GCSToken(
        ) {
        balanceOf[msg.sender] = 210000000000000000;              // Give the creator all initial tokens
        totalSupply = 210000000000000000;                        // Update total supply
        name = "Gamechain System";                                   // Set the name for display purposes
        symbol = "GCS";                              // Set the symbol for display purposes
        decimals = 8;                            // Amount of decimals for display purposes
        
    }
    
   

    /* Send coins */
    function transfer(address _to, uint256 _value) {
        if (_to == 0x0) throw;                               // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /* Approve and then communicate the approved contract in a single tx */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }        

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if (_to == 0x0) throw;                                // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[_from] < _value) throw;                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw;  // Check for overflows
        if (_value > allowance[_from][msg.sender]) throw;     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update balances first
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                           // Subtract from the sender
        balanceOf[_to] += _value;                             // Add the same to the recipient
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract if it has code (callback hook)
        if (isContract(_to)) {
            // Using low-level call to mimic callback and reentrancy exposure (no try/catch in 0.4.8)
            _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value);
        }
        
        // Update allowance AFTER external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Helper function to check if address is a contract
    function isContract(address addr) internal constant returns (bool) {
        uint size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
}
