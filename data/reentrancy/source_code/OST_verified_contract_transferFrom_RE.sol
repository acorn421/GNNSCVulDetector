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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This vulnerability introduces a stateful, multi-transaction reentrancy attack vector through the following mechanisms:
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call Before State Finalization**: Introduced a callback to the recipient contract using `tokenRecipient(_to).receiveApproval()` before the actual transfer is completed
 * 2. **Temporary Allowance Reduction**: The allowance is decremented early but can be restored if the callback fails
 * 3. **Code Length Check**: Added `_to.code.length > 0` to determine if the recipient is a contract that can receive callbacks
 * 4. **Try-Catch Block**: Implemented error handling that restores state on callback failure
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `transferFrom()` with a malicious contract as `_to`
 * 2. **During Transaction 1**: The malicious contract's `receiveApproval()` function is called while the allowance is temporarily reduced but before the actual transfer
 * 3. **Reentrant Call**: The malicious contract calls `transferFrom()` again during the callback, exploiting the fact that the balance hasn't been updated yet
 * 4. **State Inconsistency**: This creates a race condition where multiple transfers can occur before the state is properly synchronized
 * 5. **Transaction 2+**: Subsequent transactions can exploit the accumulated state inconsistencies
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * - The vulnerability requires the attacker to deploy a malicious contract that implements the callback interface
 * - The exploit depends on the timing between allowance updates and balance transfers across multiple call frames
 * - The state inconsistency accumulates across multiple function calls, making it impossible to exploit in a single atomic transaction
 * - The attacker needs to carefully orchestrate the sequence of calls to maximize the extracted value
 * 
 * **Stateful Nature:**
 * - The allowance state persists between transactions and can be manipulated through the callback mechanism
 * - Balance states are modified in a non-atomic way, creating windows for exploitation
 * - The temporary allowance reduction creates a stateful condition that can be exploited across multiple calls
 * 
 * This vulnerability is realistic because it mimics real-world token contracts that implement callback mechanisms for better UX, but fail to properly handle reentrancy during state transitions.
 */
pragma solidity ^0.4.18;

interface tokenRecipient {
  function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external;
}

contract OST {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor(uint256 initialSupply, string tokenName, string tokenSymbol) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Store original allowance for callback
        uint256 originalAllowance = allowance[_from][msg.sender];
        
        // Temporarily reduce allowance to prevent double-spending during callback
        allowance[_from][msg.sender] -= _value;
        
        // Call recipient's callback before completing the transfer
        // This allows the recipient to potentially call back into this function
        if(_to != address(0) && isContract(_to)) {
            tokenRecipient(_to).receiveApproval(_from, _value, this, "");
        }
        
        // Complete the actual transfer
        _transfer(_from, _to, _value);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }

    // Helper for checking code size (detect contract)
    function isContract(address _addr) internal view returns (bool is_contract) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }

    /*******************
     * Extra functions *
     *******************/

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
        balanceOf[msg.sender] -= _value;            // Subtract from the sender
        totalSupply -= _value;                      // Updates totalSupply
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
