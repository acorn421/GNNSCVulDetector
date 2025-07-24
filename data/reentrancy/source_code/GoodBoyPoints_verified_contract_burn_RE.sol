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
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Stateful Multi-Transaction Reentrancy Vulnerability Injection**
 * 
 * **1. Specific Changes Made:**
 * - Added two new state variables: `burnRequests` and `burnProcessing` mappings to track burn operations across transactions
 * - Introduced an external call to `msg.sender.call()` before state updates, creating a reentrancy opportunity
 * - Moved critical state updates (balance and totalSupply modifications) to occur AFTER the external call
 * - Added conditional logic around state updates using the `burnProcessing` flag
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Initial Setup):**
 * - Attacker calls `burn(100)` with 100 tokens
 * - Function stores `burnRequests[attacker] = 100` and sets `burnProcessing[attacker] = true`
 * - External call to attacker's contract triggers `onBurnNotification(100)`
 * 
 * **Transaction 2 (Reentrancy Attack):**
 * - During the external call in Transaction 1, attacker's contract calls `burn(50)` again
 * - Since `burnProcessing[attacker]` is still `true` from the first call, the second call can proceed
 * - The balance check passes because the first transaction hasn't updated balances yet
 * - Second call sets `burnRequests[attacker] = 50` and makes another external call
 * 
 * **Transaction 3+ (State Manipulation):**
 * - The attacker can manipulate the `burnProcessing` and `burnRequests` state across multiple calls
 * - By carefully timing multiple `burn()` calls, the attacker can bypass balance checks
 * - The vulnerability allows burning more tokens than the attacker actually owns
 * 
 * **3. Why Multiple Transactions Are Required:**
 * 
 * **State Persistence Requirement:**
 * - The vulnerability relies on the `burnProcessing` and `burnRequests` mappings maintaining state between function calls
 * - The attacker needs to set up the initial state in one transaction, then exploit it in subsequent calls
 * 
 * **Timing Dependencies:**
 * - The exploit requires the first transaction to be in progress (external call pending) when the second transaction begins
 * - This creates a race condition that can only be exploited across multiple transactions
 * 
 * **Accumulated State Manipulation:**
 * - The attacker must build up a vulnerable state across multiple calls where `burnProcessing` is true but balances haven't been updated
 * - Each successful reentrancy call further manipulates the stored state, requiring sequential transactions
 * 
 * **External Call Dependency:**
 * - The vulnerability depends on the external call creating a window where internal state is inconsistent
 * - This window can only be exploited by making additional function calls while the original call is still executing
 * 
 * **Real-World Exploitation:**
 * An attacker would deploy a malicious contract that implements `onBurnNotification()` to immediately call `burn()` again, creating a reentrancy loop that allows burning more tokens than owned by exploiting the stateful nature of the `burnProcessing` flag across multiple transaction contexts.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract GoodBoyPoints {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 0;
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
    function GoodBoyPoints(
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
// Additional state variable needed for multi-transaction exploitation
    mapping(address => uint256) public burnRequests;
    mapping(address => bool) public burnProcessing;
    
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        
        // Store burn request for potential processing
        burnRequests[msg.sender] = _value;
        burnProcessing[msg.sender] = true;
        
        // External call to notify burn service (creates reentrancy opportunity)
        if (extcodesize(msg.sender) > 0) {
            // This is how you check code size in Solidity 0.4.x as .code isn't available
            msg.sender.call(
                abi.encodeWithSignature("onBurnNotification(uint256)", _value)
            );
            // Don't revert on failed notification
        }
        
        // State updates occur AFTER external call (vulnerable to reentrancy)
        if (burnProcessing[msg.sender]) {
            balanceOf[msg.sender] -= _value;            // Subtract from the sender
            totalSupply -= _value;                      // Updates totalSupply
            burnProcessing[msg.sender] = false;
            burnRequests[msg.sender] = 0;
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

    // Helper for 0.4.x to get code size (as .code is not available):
    function extcodesize(address _addr) internal view returns (uint256 size) {
        assembly { size := extcodesize(_addr) }
    }
}
