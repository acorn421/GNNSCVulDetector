/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a burn notification contract before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `BurnNotificationInterface(burnNotificationContract).onBurnInitiated(msg.sender, _value)` before state updates
 * 2. The external call occurs after the balance check but before balance deduction
 * 3. This violates the Checks-Effects-Interactions pattern by placing external calls before state modifications
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1**: Attacker calls burn() with amount X, triggering the external callback
 * 2. **Callback Execution**: The malicious notification contract can call burn() again recursively
 * 3. **State Persistence**: The original balance check passes for both calls since state hasn't been updated yet
 * 4. **Transaction 2+**: Subsequent transactions can exploit the accumulated state inconsistencies
 * 5. **Exploitation**: The attacker can burn more tokens than their balance through coordinated multi-transaction calls
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability exploits the persistent state of `balanceOf` and `totalSupply` across transactions
 * - Initial transaction sets up the reentrancy conditions through the external callback
 * - Subsequent transactions can exploit the state inconsistencies created by the first transaction
 * - The external contract can maintain state between transactions to coordinate the attack
 * - Gas limitations prevent single-transaction exploitation, requiring multiple coordinated calls
 * 
 * **Realistic Context**: This represents a common pattern where tokens implement burn notifications for external systems (like staking contracts, governance systems, or burn tracking), making the vulnerability realistic and subtle.
 */
pragma solidity ^0.4.25;

contract SenbitTokenOffering {
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
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    
    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    // Added missing variable and interface
    address public burnNotificationContract;
    
    // Moved interface declaration outside contract (required in Solidity 0.4.x)
    /* Interface for external burn notification */
}

interface BurnNotificationInterface {
    function onBurnInitiated(address sender, uint256 value) external;
}

contract SenbitTokenOfferingSafe is SenbitTokenOffering {
    /* Initializes contract with initial supply tokens to the creator of the contract */
    constructor() public {
        balanceOf[msg.sender] = 300000000 * (10**18); // Give the creator all initial tokens
        totalSupply = 300000000 * (10**18);          // Update total supply
        name = "Senbit Token Offering";            // Set the name for display purposes
        symbol = "STO";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
    }

    /* Internal transfer, only can be called by this contract */
    function _transfer(address _from, address _to, uint _value) internal {
        require (_to != 0x0);                               // Prevent transfer to 0x0 address. Use burn() instead
        require (balanceOf[_from] >= _value);                // Check if the sender has enough
        require (balanceOf[_to] + _value > balanceOf[_to]); // Check for overflows
        balanceOf[_from] -= _value;                         // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        Transfer(_from, _to, _value);
    }

    /// @notice Send `_value` tokens to `_to` from your account
    /// @param _to The address of the recipient
    /// @param _value the amount to send
    function transfer(address _to, uint256 _value) public{
        _transfer(msg.sender, _to, _value);
    }

    /// @notice Send `_value` tokens to `_to` in behalf of `_from`
    /// @param _from The address of the sender
    /// @param _to The address of the recipient
    /// @param _value the amount to send
    function transferFrom(address _from, address _to, uint256 _value) public  returns (bool success) {
        require (_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    /// @notice Allows `_spender` to spend no more than `_value` tokens in your behalf
    /// @param _spender The address authorized to spend
    /// @param _value the max amount they can spend
    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }


    /// @notice Remove `_value` tokens from the system irreversibly
    /// @param _value the amount of money to burn
    function burn(uint256 _value) public returns (bool success) {
        require (balanceOf[msg.sender] >= _value);            // Check if the sender has enough
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add burn callback to external contract before state updates
        if (burnNotificationContract != address(0)) {
            BurnNotificationInterface(burnNotificationContract).onBurnInitiated(msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                // Check if the targeted balance is enough
        require(_value <= allowance[_from][msg.sender]);    // Check allowance
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        Burn(_from, _value);
        return true;
    }
}
