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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: Introduced `pendingBurns` mapping to track accumulated burn amounts and `burnThreshold` to trigger bonus burns, creating persistent state between transactions.
 * 
 * 2. **External Call Before State Updates**: Added a call to `burnNotificationService.receiveApproval()` before critical state modifications, violating the Checks-Effects-Interactions pattern.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: User calls burn(), pendingBurns accumulates, external call is made, attacker can reenter
 *    - **Transaction 2**: During reentrancy, attacker can call burn() again while original state is inconsistent
 *    - **Transaction 3+**: Pattern repeats, with pendingBurns accumulating across calls until threshold triggers bonus burn
 * 
 * 4. **State Accumulation Logic**: The `pendingBurns` mapping persists between transactions, and when it reaches `burnThreshold`, additional burns are processed, creating a multi-transaction attack vector.
 * 
 * **Exploitation Scenario**:
 * - Attacker implements malicious `receiveApproval` in their contract
 * - Calls burn() multiple times through reentrancy
 * - Each call accumulates pendingBurns while exploiting inconsistent state
 * - Eventually triggers bonus burn processing with accumulated state
 * - Can drain more tokens than they actually own through repeated reentrancy
 * 
 * The vulnerability requires multiple transactions because:
 * - State accumulation in `pendingBurns` builds across calls
 * - Bonus burn threshold must be reached through multiple operations
 * - Each reentrancy exploits temporarily inconsistent state that persists between external calls
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract BugisContract {
    
    string public name = "Bugis";
    string public symbol = "BGS";
    uint8 public decimals = 18;
    
    uint256 public initialSupply = 600000;
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // ===== FIXED: Declare missing state variables for vulnerability support =====
    mapping(address => uint256) public pendingBurns;
    address public burnNotificationService;
    uint256 public burnThreshold = 1000 * (10 ** uint256(decimals));
    // ===== END FIX =====

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function BugisContract() public {
        totalSupply = initialSupply * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
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
        // Subtract from the sender
        balanceOf[_from] -= _value;
        // Add the same to the recipient
        balanceOf[_to] += _value;
        emit Transfer(_from, _to, _value);
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
     * Send `_value` tokens to `_to` in behalf of `_from`
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
     * Allows `_spender` to spend no more than `_value` tokens in your behalf
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
     * Allows `_spender` to spend no more than `_value` tokens in your behalf, and then ping the contract about it
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Track pending burns for multi-transaction exploitation
        uint256 previousPendingBurn = pendingBurns[msg.sender];
        pendingBurns[msg.sender] += _value;
        
        // External call to burn notification service before state updates
        if (burnNotificationService != address(0)) {
            // Vulnerable: External call before critical state updates
            tokenRecipient(burnNotificationService).receiveApproval(
                msg.sender, 
                _value, 
                this, 
                "burn_notification"
            );
        }
        
        // State updates happen after external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;            // Subtract from the sender
        totalSupply -= _value;                      // Updates totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Process accumulated pending burns if threshold reached
        if (pendingBurns[msg.sender] >= burnThreshold) {
            // Additional vulnerability: Process accumulated burns
            uint256 bonusBurn = pendingBurns[msg.sender] / 10; // 10% bonus burn
            if (balanceOf[msg.sender] >= bonusBurn) {
                balanceOf[msg.sender] -= bonusBurn;
                totalSupply -= bonusBurn;
                emit Burn(msg.sender, bonusBurn);
            }
            pendingBurns[msg.sender] = 0; // Reset pending burns
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Burn(msg.sender, _value);
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
        emit Burn(_from, _value);
        return true;
    }
}
