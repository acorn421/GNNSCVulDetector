/*
 * ===== SmartInject Injection Details =====
 * Function      : increaseSupply
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a governance contract AFTER the balance state update. This creates a classic checks-effects-interactions pattern violation where:
 * 
 * 1. **Multi-Transaction Setup**: The vulnerability requires multiple transactions:
 *    - Transaction 1: Owner calls setGovernanceContract() to set a malicious contract address
 *    - Transaction 2: Owner calls increaseSupply() which triggers the external call to the malicious governance contract
 * 
 * 2. **Stateful Exploitation**: The malicious governance contract can:
 *    - Re-enter increaseSupply() multiple times before the first call completes
 *    - Each re-entry accumulates additional balance increases for the owner
 *    - The state changes persist across the nested calls, amplifying the effect
 * 
 * 3. **Realistic Integration**: The governance notification mechanism is a realistic feature that could exist in production token contracts for transparency and compliance.
 * 
 * 4. **Exploitation Sequence**:
 *    - Attacker deploys malicious governance contract
 *    - Owner (if compromised) or attacker (if they gain owner privileges) sets the malicious contract as governance
 *    - When increaseSupply() is called, the malicious contract's notifySupplyIncrease() function re-enters increaseSupply() multiple times
 *    - Each re-entry increases the owner's balance by the original _value amount
 *    - The attack accumulates state changes across multiple nested function calls within the same transaction
 * 
 * This vulnerability demonstrates how external calls after state changes can enable sophisticated reentrancy attacks that require both state setup (setting governance contract) and execution (calling increaseSupply) across multiple transactions.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

interface GovernanceInterface {
    function notifySupplyIncrease(address owner, uint _value) external;
}

contract TAToken {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;
    
    address public owner;
    address public governanceContract;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    modifier onlyOwner {
        if (msg.sender != owner) revert();
        _;
    }
    
    /**
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor() public {
        totalSupply = 150000000 * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = 70000000 * 10 ** uint256(decimals);                // Give the creator all initial tokens
        name = "Three and the chain";                                   // Set the name for display purposes
        symbol = "TA";                               // Set the symbol for display purposes
        owner = msg.sender;
    }
    
    /**
     * transferOwnership
     */
    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
    
    /**
     * Increase Owner token
     */
    function increaseSupply(uint _value) onlyOwner public returns (bool)  {
        //totalSupply = safeAdd(totalSupply, value);
        balanceOf[owner] += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify governance contract about supply increase
        if (governanceContract != address(0)) {
            GovernanceInterface(governanceContract).notifySupplyIncrease(owner, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }
    
    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        // Prevent transfer to 0x0 address. Use burn() instead
        require(_to != 0x0);
        // Check if the sender has enough
        require(balanceOf[_from] >= _value);
        // Check for overflows
        require(balanceOf[_to] + _value > balanceOf[_to]);
        // Save this for an assertion in the future
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        // Subtract from the _spender
        balanceOf[_from] -= _value;
        // Add the same to the recipient
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        // Asserts are used to use static analysis to find bugs in your code. They should never fail
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    /**
     * Transfer tokens
     *
     * Send `_value` tokens to `_to` from your account
     *
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    /**
     * Transfer tokens from other address
     *
     * Send `_value` tokens to `_to` on behalf of `_from`
     *
     * @param _from The address of the sender
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    /**
     * Set allowance for other address
     *
     * Allows `_spender` to spend no more than `_value` tokens on your behalf
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /**
     * Set allowance for other address and notify
     *
     * Allows `_spender` to spend no more than `_value` tokens on your behalf, and then ping the contract about it
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     * @param _extraData some extra information to send to the approved contract
     */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    /**
     * Destroy tokens
     *
     * Remove `_value` tokens from the system irreversibly
     *
     * @param _value the amount of money to burn
     */
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        balanceOf[msg.sender] -= _value;            // Subtract from the sender
        totalSupply -= _value;                      // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    /**
     * Destroy tokens from other account
     *
     * Remove `_value` tokens from the system irreversibly on behalf of `_from`.
     *
     * @param _from the address of the sender
     * @param _value the amount of money to burn
     */
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
