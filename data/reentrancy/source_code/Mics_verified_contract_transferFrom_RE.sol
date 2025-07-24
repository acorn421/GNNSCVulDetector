/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before updating the allowance state. This creates a window where the allowance hasn't been decremented yet, allowing malicious contracts to exploit the vulnerability across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added a conditional external call to `_to.call()` that invokes `onTokenReceived` if the recipient is a contract
 * 2. Moved the allowance state update (`allowance[_from][msg.sender] -= _value`) to occur AFTER the external call
 * 3. The external call happens before state changes, creating a classic reentrancy vulnerability
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - User approves attacker contract for 100 tokens: `approve(attackerContract, 100)`
 * - Allowance state: `allowance[user][attackerContract] = 100`
 * 
 * **Transaction 2 (Initial Attack):**
 * - Attacker calls `transferFrom(user, maliciousContract, 50)`
 * - Flow: allowance check passes (50 <= 100) → external call to maliciousContract.onTokenReceived()
 * - During the external call, the malicious contract reenters and calls `transferFrom(user, anotherAddress, 50)` again
 * - The second call passes the allowance check (50 <= 100) because allowance hasn't been decremented yet
 * - Result: 100 tokens transferred using only 50 tokens of allowance
 * 
 * **Transaction 3 (Potential Further Exploitation):**
 * - If any allowance remains, the pattern can be repeated across multiple transactions
 * - Each transaction can exploit the time window between allowance check and allowance update
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Persistence**: The allowance mapping persists between transactions, creating opportunities for accumulated exploitation
 * 2. **Reentrancy Window**: The vulnerability exists in the window between the allowance check and the allowance update, which can be exploited multiple times
 * 3. **Stateful Nature**: The attack relies on the allowance state not being properly updated before external calls, requiring multiple function calls to fully exploit
 * 4. **Incremental Exploitation**: Each transaction can potentially drain more tokens than the allowance should permit, with the full impact realized across multiple calls
 * 
 * This creates a realistic reentrancy vulnerability that requires multiple transactions to be fully exploited, as the attacker needs to set up allowances and then exploit them across multiple calls to maximize the damage.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract Mics {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function Mics() public {
        totalSupply = 100000000 * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = "Mics";                                   // Set the name for display purposes
        symbol = "MICS";                               // Set the symbol for display purposes
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
     * Send `_value` tokens to `_to` on behalf of `_from`
     *
     * @param _from The address of the sender
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // VULNERABILITY: External call to recipient before state update
        // This simulates a token transfer notification system
        // Removed invalid 'if(_to != address(0) && _to.callcode.length > 0)' as 'callcode' is not a member
        if(isContract(_to)) {
            // Call recipient's onTokenReceived function if it's a contract
            _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, msg.sender, _value);
            // Continue execution regardless of call result for compatibility
        }
        // State update happens AFTER external call - creates reentrancy window
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function isContract(address _addr) internal view returns (bool is_contract) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
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
}
