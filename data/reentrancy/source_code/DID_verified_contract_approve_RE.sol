/*
 * ===== SmartInject Injection Details =====
 * Function      : approve
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * This injection introduces a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the spender contract about approval changes. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added a check to determine if the spender is a contract using `_spender.code.length > 0`
 * 2. Introduced an external call to `_spender.call()` with the signature `onApprovalReceived(address,uint256)`
 * 3. The external call occurs BEFORE the state update to the allowance mapping
 * 4. The call continues execution even if the notification fails
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: Attacker deploys a malicious contract that implements `onApprovalReceived()`
 * 2. **Transaction 2**: Victim calls `approve()` with the malicious contract address as spender
 * 3. **During Transaction 2**: The malicious contract's `onApprovalReceived()` is called, which can:
 *    - Read the current allowance state (still old value)
 *    - Call `transferFrom()` to drain tokens using any existing allowance
 *    - Call `approve()` again recursively to manipulate allowances
 * 4. **After the reentrant calls**: The original `approve()` continues and sets the allowance
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability requires the victim to first establish some allowance or token balance (Transaction 1)
 * - The attacker must deploy their malicious contract (separate transaction)
 * - The actual exploit happens when the victim calls approve() with the malicious contract (Transaction 2)
 * - The exploit relies on the accumulated state (existing allowances, token balances) from previous transactions
 * - The attacker can only drain tokens if there are existing allowances or balances to exploit
 * 
 * **Stateful Nature:**
 * - The vulnerability exploits the persistent state in the `allowance` mapping
 * - It requires accumulated token balances and allowances from previous transactions
 * - The attack effectiveness depends on the contract's historical state, not just a single transaction's state
 * 
 * This creates a realistic approval notification mechanism that could appear in production code while introducing a critical reentrancy vulnerability that requires multiple transactions and state accumulation to exploit effectively.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

/**
 * v0.4.21+commit.dfe3193c
 */
contract DID {
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
    function DID() public {
        totalSupply = 20 * 100000000 * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = "Dage Identification";  // Set the name for display purposes
        symbol = "DID";                               // Set the symbol for display purposes
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
        require((_value == 0) || (allowance[msg.sender][_spender] == 0));
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Check if spender is a contract and supports approval notifications
        uint length;
        assembly { length := extcodesize(_spender) }
        if (length > 0) {
            // Notify spender about the approval before updating state
            _spender.call(
                abi.encodeWithSignature("onApprovalReceived(address,uint256)", msg.sender, _value)
            );
            // Continue even if notification fails
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
