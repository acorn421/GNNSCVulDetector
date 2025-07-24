/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding:
 * 1. A `burningInProgress` mapping to track ongoing burn operations
 * 2. A `burnFeeRecipient` address for external contract notifications
 * 3. An external call to `BurnFeeRecipient.notifyBurn()` placed after the balance check but before state updates
 * 4. The external call violates the Checks-Effects-Interactions pattern
 * 
 * **Multi-Transaction Exploitation:**
 * - Transaction 1: User calls burn() with amount X, triggering external call to burnFeeRecipient
 * - During external call: The recipient contract can call back into burn() since burningInProgress is reset after the external call
 * - The reentrant call sees the original balance (before subtraction) and can burn additional tokens
 * - Transaction 2+: Each reentrant call can exploit the stale balance state
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the external contract to implement a callback mechanism
 * - The burningInProgress flag prevents simple single-transaction reentrancy
 * - Exploitation requires coordinated state manipulation across multiple calls
 * - The attacker must deploy a malicious burnFeeRecipient contract that implements the callback attack
 * - State persistence (balanceOf, burningInProgress) across transactions enables the exploit
 * 
 * **Additional State Variables Needed:**
 * ```solidity
 * mapping (address => bool) public burningInProgress;
 * address public burnFeeRecipient;
 * 
 * interface BurnFeeRecipient {
 *     function notifyBurn(address burner, uint256 amount) external;
 * }
 * ```
 */
pragma solidity ^0.4.13;

contract owned {
    address public owner;
    function owned() public {
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
contract tokenRecipient {
     function receiveApproval(address from, uint256 value, address token, bytes extraData) public;
}
contract token {
    /*Public variables of the token */
    string public name; string public symbol; uint8 public decimals; uint256 public totalSupply;
    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);
    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);
    
    // Added to preserve vulnerability code referencing these variables
    mapping(address => bool) public burningInProgress;
    address public burnFeeRecipient;
    // Interface for BurnFeeRecipient contract (changed from misplaced contract to interface)
    
    interface IBurnFeeRecipient {
        function notifyBurn(address from, uint256 value) external;
    }

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function token() public {
        balanceOf[msg.sender] = 10000000000000000; 
        totalSupply = 10000000000000000; 
        name = "BCB"; 
        symbol =  "฿";
        decimals = 8; 
    }
    /* Internal transfer, only can be called by this contract */
    function _transfer(address _from, address _to, uint _value) internal {
        require (_to != 0x0); 
        require (balanceOf[_from] > _value); 
        require (balanceOf[_to] + _value > balanceOf[_to]); 
        balanceOf[_from] -= _value; 
        balanceOf[_to] += _value; 
        Transfer(_from, _to, _value);
    }

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require (_value < allowance[_from][msg.sender]); 
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value)
        public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }
    /// @notice Remove `_value` tokens from the system irreversibly
    /// @param _value the amount of money to burn
    function burn(uint256 _value) public returns (bool success) {
        require (balanceOf[msg.sender] > _value); // Check if the sender has enough
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        require (!burningInProgress[msg.sender]); // Check if not already burning
        
        burningInProgress[msg.sender] = true; // Mark burning as in progress
        
        // Notify burn fee recipient contract before updating state
        if (burnFeeRecipient != address(0)) {
            IBurnFeeRecipient(burnFeeRecipient).notifyBurn(msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value; // Subtract from the sender
        totalSupply -= _value; // Updates totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        burningInProgress[msg.sender] = false; // Reset burning flag
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value); // Check if the targeted balance is enough
        require(_value <= allowance[_from][msg.sender]); // Check allowance
        balanceOf[_from] -= _value; // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value; // Subtract from the sender's allowance
        totalSupply -= _value; // Update totalSupply
        Burn(_from, _value);
        return true;
    }
}

contract BcbToken is owned, token {
    mapping (address => bool) public frozenAccount;
    /* This generates a public event on the blockchain that will notify clients */
    event FrozenFunds(address target, bool frozen);

    function _transfer(address _from, address _to, uint _value) internal {
        require (_to != 0x0); 
        
        require(msg.sender != _to);
        require (balanceOf[_from] > _value); // Check if the sender has enough
        require (balanceOf[_to] + _value > balanceOf[_to]); 
        require(!frozenAccount[_from]); // Check if sender is frozen
        require(!frozenAccount[_to]); // Check if recipient is frozen
        balanceOf[_from] -= _value; // Subtract from the sender
        balanceOf[_to] += _value; // Add the same to the recipient
        Transfer(_from, _to, _value);
    }

    function freezeAccount(address target, bool freeze) onlyOwner public {
        frozenAccount[target] = freeze;
        FrozenFunds(target, freeze);
    }
}
