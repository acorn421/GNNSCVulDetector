/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added Persistent State Variables**: 
 *    - `pendingTransfers` mapping to track pending transfer amounts
 *    - `transferInitiated` mapping to track transfer state across transactions
 * 
 * 2. **Introduced External Call Before State Updates**:
 *    - Added external call to `tokenRecipient(_to).receiveApproval()` for contract recipients
 *    - This call happens BEFORE the actual token transfer is completed
 *    - The external call can trigger reentrancy back into the transfer function
 * 
 * 3. **Created Multi-Transaction Dependency**:
 *    - First transaction: Sets up pending state and makes external call
 *    - Second transaction: Completes the transfer based on pending state
 *    - The vulnerability requires this sequence to be exploitable
 * 
 * 4. **Exploitation Pattern**:
 *    - **Transaction 1**: Attacker calls transfer() to malicious contract
 *    - **During external call**: Malicious contract re-enters transfer() function
 *    - **State manipulation**: Attacker can manipulate pendingTransfers mapping
 *    - **Transaction 2**: Attacker calls transfer() again to complete with manipulated state
 *    - **Result**: Attacker can drain more tokens than they should be able to
 * 
 * 5. **Why Multi-Transaction is Required**:
 *    - The vulnerability depends on the persistent state between calls
 *    - Single transaction reentrancy would just complete the same transfer
 *    - Multi-transaction allows accumulation of pending transfers and state manipulation
 *    - The attacker needs separate transactions to set up the vulnerable state and then exploit it
 * 
 * This creates a realistic vulnerability where the contract attempts to notify recipient contracts about incoming transfers, but fails to properly protect against reentrancy attacks that span multiple transactions.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

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
    mapping(address => uint256) public pendingTransfers;
    mapping(address => bool) public transferInitiated;

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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
// State variables to add to contract (for context):
// mapping(address => uint256) public pendingTransfers;
// mapping(address => bool) public transferInitiated;

    function transfer(address _to, uint256 _value) public {
        // Check if this is continuing a pending transfer
        if (transferInitiated[msg.sender]) {
            // Complete the pending transfer
            uint256 pendingAmount = pendingTransfers[msg.sender];
            pendingTransfers[msg.sender] = 0;
            transferInitiated[msg.sender] = false;
            _transfer(msg.sender, _to, pendingAmount);
            return;
        }
        
        // For new transfers, check if recipient is a contract
        if (isContract(_to)) {
            // Set up pending transfer state
            pendingTransfers[msg.sender] = _value;
            transferInitiated[msg.sender] = true;
            
            // External call to notify recipient contract (vulnerable to reentrancy)
            // Fallback for try/catch not available in Solidity 0.4.16. Use low-level call.
            // Suppress error and fallback as per injected logic.
            bool callSuccess = true;
            bytes memory data = abi.encodeWithSignature("receiveApproval(address,uint256,address,bytes)", msg.sender, _value, this, "");
            // Using low-level call as try/catch unavailable in 0.4.16
            assembly {
                callSuccess := call(gas, _to, 0, add(data, 32), mload(data), 0, 0)
            }
            if (!callSuccess) {
                // If notification fails, reset state and do direct transfer
                pendingTransfers[msg.sender] = 0;
                transferInitiated[msg.sender] = false;
                _transfer(msg.sender, _to, _value);
            }
            // else, state remains pending until next call
        } else {
            // Direct transfer for EOA recipients
            _transfer(msg.sender, _to, _value);
        }
    }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    // Helper function to check if _addr is a contract (Solidity 0.4.x way)
    function isContract(address _addr) internal view returns (bool is_contract) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
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
