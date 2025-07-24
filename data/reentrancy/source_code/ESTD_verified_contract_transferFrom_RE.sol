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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added Pending Transfer State**: Created a pendingTransfers mapping that persists between transactions, tracking incomplete transfers using a unique transferId.
 * 
 * 2. **External Call Before State Updates**: Added an external call to the recipient address (_to) before updating the allowance, creating a reentrancy window where the contract state is inconsistent.
 * 
 * 3. **Multi-Transaction Exploitation Path**: The vulnerability requires multiple transactions to exploit:
 *    - **Transaction 1**: Legitimate transferFrom call creates pending transfer state and makes external call
 *    - **Transaction 2+**: During the external call, malicious contract can call transferFrom again, exploiting the fact that allowance hasn't been updated yet
 * 
 * 4. **State Persistence**: The pendingTransfers mapping maintains state between transactions, allowing attackers to identify and exploit incomplete transfers.
 * 
 * **Multi-Transaction Exploitation Scenario**:
 * - **Step 1**: Attacker calls transferFrom(victim, attackerContract, 100) with victim having 100 allowance
 * - **Step 2**: Function makes external call to attackerContract.onTokenReceive()
 * - **Step 3**: Inside onTokenReceive(), attacker calls transferFrom(victim, attackerContract, 100) again
 * - **Step 4**: Since allowance hasn't been updated yet, the second call succeeds, draining 200 tokens with only 100 allowance
 * 
 * **Why Multi-Transaction is Required**:
 * - The vulnerability cannot be exploited in a single transaction because it requires the external call to trigger the reentrancy
 * - The pending transfer state persists between the initial call and the reentrant call
 * - Multiple function invocations are needed to exploit the time window between external call and state update
 * - The attack requires coordination between the initial transferFrom call and the reentrant call triggered by the external callback
 * 
 * This creates a realistic reentrancy vulnerability that mirrors real-world token contract exploits where external calls to recipient contracts create opportunities for reentrant attacks on allowance mechanisms.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract ESTD {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // Add missing state variable for pendingTransfers
    mapping (bytes32 => uint256) public pendingTransfers;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
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
     * Send `_value` tokens to `_to` on behalf of `_from`
     *
     * @param _from The address of the sender
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Create a pending transfer state that persists between transactions
        bytes32 transferId = keccak256(_from, _to, _value, block.timestamp);
        
        // First transaction: Set up pending transfer and make external call
        if (pendingTransfers[transferId] == 0) {
            pendingTransfers[transferId] = _value;
            
            // External call to recipient before state update - vulnerable to reentrancy
            if (isContract(_to)) {
                // call onTokenReceive if it exists
                _to.call(abi.encodeWithSignature("onTokenReceive(address,uint256,bytes32)", _from, _value, transferId));
                // Continue regardless of call success for compatibility
            }
            
            // State update happens after external call - creates reentrancy window
            allowance[_from][msg.sender] -= _value;
            _transfer(_from, _to, _value);
            
            // Clear pending transfer after successful completion
            delete pendingTransfers[transferId];
        }
        // Second+ transactions: If pending transfer exists, attacker can exploit remaining allowance
        else {
            // Vulnerability: Attacker can call transferFrom again with same parameters
            // before the first transaction completes, exploiting remaining allowance
            uint256 remainingAllowance = allowance[_from][msg.sender];
            if (remainingAllowance >= _value) {
                allowance[_from][msg.sender] -= _value;
                _transfer(_from, _to, _value);
            }
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }

    // isContract utility function for pre-0.5.0
    function isContract(address _addr) internal view returns (bool result) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
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
