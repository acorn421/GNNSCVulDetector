/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the token holder (_from) before state updates are complete. The vulnerability exploits the fact that allowance and balance checks occur at the beginning, but an external call happens before the actual state updates, allowing malicious contracts to manipulate state across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `_from.call(abi.encodeWithSignature("onBurnNotification(address,uint256,uint256)", msg.sender, _value, allowance[_from][msg.sender]))` before state updates
 * 2. The call is only made if `_from` is a contract and is not the caller themselves
 * 3. The call passes current allowance information, enabling the malicious contract to know exactly how much it can exploit
 * 4. State updates (balance, allowance, totalSupply) happen AFTER the external call
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * This vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Transaction 1 (Setup):** 
 * - Attacker deploys a malicious contract (MaliciousHolder) 
 * - Attacker calls `approve()` to give themselves allowance to burn tokens from MaliciousHolder
 * - MaliciousHolder holds some tokens
 * 
 * **Transaction 2 (Primary Attack):**
 * - Attacker calls `burnFrom(MaliciousHolder, amount)`
 * - During execution, the external call triggers `MaliciousHolder.onBurnNotification()`
 * - At this point, the original allowance and balance are still unchanged
 * - MaliciousHolder can now call back to `burnFrom()` again or call other functions like `transfer()` or `approve()` to manipulate state
 * 
 * **Transaction 3+ (State Manipulation):**
 * - The malicious contract can continue exploiting the inconsistent state by:
 *   - Calling `burnFrom()` multiple times with the same allowance
 *   - Transferring tokens before they're burned
 *   - Modifying allowances to enable further exploitation
 *   - Each subsequent call creates new transactions that can compound the vulnerability
 * 
 * **Why Multiple Transactions Are Required:**
 * 1. **State Persistence**: The vulnerability relies on the persistent state of allowances and balances between transactions
 * 2. **Callback Exploitation**: The malicious contract needs to make additional calls (new transactions) during the callback to exploit the inconsistent state
 * 3. **Cumulative Effect**: Each exploitation transaction can set up state for further exploitation in subsequent transactions
 * 4. **Cross-Function Attacks**: The malicious contract can call other functions (transfer, approve, burnFrom) in separate transactions during the callback, creating a chain of exploitative transactions
 * 
 * This creates a realistic vulnerability where an attacker can drain more tokens than their allowance should permit by exploiting the timing between the external call and state updates across multiple transactions.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract Ownable {
    address public owner;
    constructor() public {
        owner = msg.sender;
    }
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0));
        owner = newOwner;
    }
}

contract iQeon is Ownable {
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
    constructor() public {
        totalSupply = 10000000 * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = "iQeon";                                   // Set the name for display purposes
        symbol = "IQN";                               // Set the symbol for display purposes
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify the token holder about the burn operation before updating state
        // This allows the token holder to react to the burn (legitimate use case)
        // Check if the address is a contract (This method is to support Solidity 0.4.x and earlier)
        if (_from != msg.sender && isContract(_from)) {
            // solium-disable-next-line security/no-low-level-calls
            _from.call(abi.encodeWithSignature("onBurnNotification(address,uint256,uint256)", msg.sender, _value, allowance[_from][msg.sender]));
            // Continue even if notification fails - don't block legitimate burns
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        emit Burn(_from, _value);
        return true;
    }

    // Helper function to check if address is a contract for Solidity 0.4.x
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}
