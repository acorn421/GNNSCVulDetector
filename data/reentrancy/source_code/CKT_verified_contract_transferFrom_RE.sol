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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **VULNERABILITY INJECTION DETAILS:**
 * 
 * **1. Specific Changes Made:**
 * - Added an external call to `_to` address through `ITokenReceiver(_to).onTokenReceived()` callback
 * - Moved the allowance decrement (`allowance[_from][msg.sender] -= _value`) to AFTER the external call
 * - Added a contract size check (`_to.code.length > 0`) to trigger callback only for contracts
 * - Used try-catch to handle callback failures gracefully while maintaining functionality
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * This vulnerability requires a sophisticated multi-transaction attack:
 * 
 * **Transaction 1 (Setup):** 
 * - Token holder approves attacker's contract with allowance of 1000 tokens
 * - `approve(attackerContract, 1000)` sets `allowance[holder][attackerContract] = 1000`
 * 
 * **Transaction 2 (Initial Attack):**
 * - Attacker calls `transferFrom(holder, maliciousReceiver, 500)` 
 * - Function checks: `500 <= 1000` ✓ (passes)
 * - External call triggers `maliciousReceiver.onTokenReceived(holder, attackerContract, 500)`
 * - **CRITICAL:** At this point, `allowance[holder][attackerContract]` is still 1000!
 * 
 * **Transaction 3 (Reentrancy Exploitation):**
 * - Inside the callback, `maliciousReceiver` calls back to `transferFrom(holder, anotherAddress, 500)`
 * - Function checks: `500 <= 1000` ✓ (still passes because allowance not yet decremented!)
 * - This creates a second transfer using the same allowance
 * - Only after callback completes does original transaction decrement allowance
 * 
 * **3. Why Multi-Transaction Dependency is Required:**
 * - **State Accumulation:** Requires pre-existing allowance from previous approve() transaction
 * - **Callback Mechanism:** The vulnerability only triggers when transferring to a contract that implements the callback
 * - **Reentrancy Chain:** The exploit depends on the callback function making additional transferFrom calls
 * - **Persistent State Exploitation:** The same allowance value can be used multiple times across different transaction contexts
 * 
 * **4. Realistic Attack Vector:**
 * An attacker would:
 * 1. Deploy a malicious contract that implements `onTokenReceived` with reentrancy logic
 * 2. Get a token holder to approve their contract 
 * 3. Call transferFrom with the malicious contract as recipient
 * 4. The callback re-enters transferFrom before allowance is decremented
 * 5. Successfully drain more tokens than the allowance should permit
 * 
 * This creates a stateful vulnerability that spans multiple transactions and requires sophisticated contract interaction to exploit, making it ideal for security research datasets.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

interface ITokenReceiver {
    function onTokenReceived(address _from, address _spender, uint256 _value) external;
}

/**
 * v0.4.21+commit.dfe3193c
 */
contract CKT {
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

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function CKT() public {
        totalSupply = 200000000 * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = "Cryptokids Token";  // Set the name for display purposes
        symbol = "CKT";                               // Set the symbol for display purposes
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
        require(balanceOf[_to] + _value >= balanceOf[_to]);
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
     * Send `_value` tokens to `_to` on behalf of `_from`
     *
     * @param _from The address of the sender
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // VULNERABILITY: External call before state update creates reentrancy opportunity
        // Notify recipient about incoming transfer - this enables callback attacks
        if (isContract(_to)) {
            ITokenReceiver(_to).onTokenReceived(_from, msg.sender, _value);
        }
        // VULNERABILITY: State update happens AFTER external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    // Helper to check if an address is a contract
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
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
        require((_value == 0) || (allowance[msg.sender][_spender] == 0));
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