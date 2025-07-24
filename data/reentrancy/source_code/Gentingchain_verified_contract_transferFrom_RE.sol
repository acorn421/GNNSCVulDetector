/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 4 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 * 3. reentrancy-events (SWC-107)
 * ... and 1 more
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Added External Calls Before State Updates**: Introduced two external calls to the recipient address (`_to.call()`) that execute BEFORE the critical state updates (allowance decrease and balance transfer).
 * 
 * 2. **Vulnerable State Sequence**: The function now follows a vulnerable pattern:
 *    - Check allowance (line 2)
 *    - External call to `onTokenTransfer` (line 7)
 *    - State update: decrease allowance (line 9) 
 *    - External call to `beforeTransferUpdate` (line 12)
 *    - Internal transfer call (line 13)
 * 
 * 3. **Callback Mechanism**: Added realistic callback functions that a malicious recipient contract could implement to re-enter the transferFrom function.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker approves themselves a large allowance (e.g., 1000 tokens)
 * - Attacker deploys a malicious recipient contract that implements the callback functions
 * 
 * **Transaction 2 (Initial Transfer):**
 * - Attacker calls `transferFrom(victim, maliciousContract, 100)` 
 * - Function checks allowance (1000 >= 100) ✓
 * - External call to `maliciousContract.onTokenTransfer()` is made
 * - **Malicious contract re-enters `transferFrom` multiple times** before original state updates occur
 * - Each re-entrant call sees the same initial allowance (1000) because state hasn't been updated yet
 * 
 * **Transaction 3+ (Continued Exploitation):**
 * - The malicious contract can continue exploiting the reentrancy across multiple transactions
 * - Each call can drain more tokens than the original allowance should permit
 * - The persistent allowance state between transactions enables continued exploitation
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Persistence**: The allowance mapping persists between transactions, allowing the attacker to set up the exploit across multiple calls.
 * 
 * 2. **Accumulated Exploitation**: The attacker needs multiple transactions to:
 *    - First: Set up the allowance and deploy malicious contract
 *    - Second: Trigger the vulnerable callback sequence
 *    - Third+: Continue exploiting the reentrancy window
 * 
 * 3. **Realistic Attack Vector**: Real-world reentrancy attacks often involve:
 *    - Preparation transactions (approvals, contract deployment)
 *    - Trigger transactions (initial vulnerable call)
 *    - Exploitation transactions (continued draining)
 * 
 * 4. **Contract Interaction Dependency**: The vulnerability relies on the interaction between the token contract and a malicious recipient contract, which must be deployed and configured across multiple transactions.
 * 
 * The vulnerability is realistic because it mimics real-world token callback patterns while introducing the classic reentrancy flaw of external calls before state updates, making it exploitable across multiple transactions through persistent state manipulation.
 */
pragma solidity ^0.4.16;
interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }
contract Gentingchain {
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
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function Gentingchain(
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
     * Send `_value` tokens to `_to` in behalf of `_from`
     *
     * @param _from The address of the sender
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Store initial allowance and balance states
        uint256 initialAllowance = allowance[_from][msg.sender];
        uint256 initialBalance = balanceOf[_from];
        
        // Vulnerable: External call to recipient BEFORE state updates
        if(_to.call(bytes4(keccak256("onTokenTransfer(address,address,uint256)")), _from, _to, _value)) {
            // State changes happen after external call - vulnerable to reentrancy
            allowance[_from][msg.sender] -= _value;
            
            // Additional external call that can trigger reentrancy
            if(_to.call(bytes4(keccak256("beforeTransferUpdate(address,uint256)")), _from, _value)) {
                _transfer(_from, _to, _value);
            } else {
                // Fallback: proceed with transfer even if callback fails
                _transfer(_from, _to, _value);
            }
        } else {
            // Fallback path: traditional transfer without callback
            allowance[_from][msg.sender] -= _value;
            _transfer(_from, _to, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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