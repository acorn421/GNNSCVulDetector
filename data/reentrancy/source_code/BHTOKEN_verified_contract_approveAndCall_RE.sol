/*
 * ===== SmartInject Injection Details =====
 * Function      : approveAndCall
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
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding state tracking mechanisms (pendingApprovals and approvalInProgress mappings) that persist between transactions. The vulnerability allows attackers to:
 * 
 * 1. **Multi-Transaction Setup**: First transaction deploys malicious contract, second transaction calls approveAndCall
 * 2. **State Accumulation**: During receiveApproval callback, malicious contract re-enters approveAndCall, accumulating pending approvals
 * 3. **Exploitation**: After the external call completes, pending approvals are processed and added to allowance without proper validation
 * 4. **Stateful Persistence**: The pendingApprovals mapping maintains state between transaction calls, enabling accumulated exploitation
 * 
 * The vulnerability requires multiple transactions because:
 * - Transaction 1: Deploy malicious contract implementing tokenRecipient
 * - Transaction 2: Call approveAndCall with malicious contract as spender
 * - During Transaction 2: Malicious contract re-enters via receiveApproval callback
 * - The re-entrant calls accumulate in pendingApprovals state
 * - After external call completes, accumulated pending approvals are processed, granting excessive allowance
 * 
 * This creates a realistic vulnerability where an attacker can obtain more allowance than intended through careful state manipulation across multiple function calls.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract BHTOKEN {
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
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function BHTOKEN(
        ) public {
        totalSupply = 10000000 * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = "BH TOKEN";                                   // Set the name for display purposes
        symbol = "BHT";                               // Set the symbol for display purposes
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping (address => uint256) public pendingApprovals;
    mapping (address => bool) public approvalInProgress;
    
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        public
        returns (bool success) {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Check if there's already an approval in progress for this spender
        if (approvalInProgress[_spender]) {
            // Add to pending approvals instead of rejecting
            pendingApprovals[_spender] += _value;
            return true;
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Mark approval as in progress before external call
            approvalInProgress[_spender] = true;
            
            // External call - vulnerable to reentrancy
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            
            // Process any pending approvals accumulated during reentrancy
            if (pendingApprovals[_spender] > 0) {
                uint256 pendingAmount = pendingApprovals[_spender];
                pendingApprovals[_spender] = 0;
                
                // This creates additional allowance without proper checks
                allowance[msg.sender][_spender] += pendingAmount;
            }
            
            // Clear the in-progress flag
            approvalInProgress[_spender] = false;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            return true;
        }
    }
}