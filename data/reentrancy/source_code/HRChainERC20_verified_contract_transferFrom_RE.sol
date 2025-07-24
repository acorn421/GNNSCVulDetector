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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract (_to) before the allowance state is updated. This creates a classic reentrancy vulnerability where:
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1**: Attacker calls transferFrom() with a malicious contract as _to
 * 2. **During Transaction 1**: The external call to _to.onTokenReceive() is made BEFORE allowance is decremented
 * 3. **Re-entrant Call**: The malicious contract's onTokenReceive() function calls transferFrom() again
 * 4. **State Exploitation**: The re-entrant call sees the original allowance value (not yet decremented), allowing multiple transfers with the same allowance
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability exploits the gap between the allowance check and the allowance update
 * - Each re-entrant call operates on stale allowance state that hasn't been updated yet
 * - The attack requires the initial transaction to trigger the external call, and subsequent re-entrant calls to exploit the inconsistent state
 * - The stateful nature means the allowance mapping persists between calls, creating the exploitable window
 * 
 * **Realistic Attack Scenario:**
 * - Attacker gets approved for 100 tokens
 * - Calls transferFrom(victim, maliciousContract, 100)
 * - maliciousContract.onTokenReceive() is called before allowance is decremented
 * - maliciousContract re-enters transferFrom() multiple times, draining more than the approved amount
 * - Each re-entrant call sees the original allowance of 100, not the decremented value
 * 
 * This vulnerability is realistic because it mimics real-world patterns where contracts notify recipients of token transfers, but violates the checks-effects-interactions pattern by making external calls before state updates.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract HRChainERC20 {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 8;
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
     */
    function HRChainERC20() public {
        totalSupply =12000000000000000;  // Update total supply with the decimal amount
        balanceOf[msg.sender] = 12000000000000000;                // Give the creator all initial tokens
        name = "Health Regimen Chain";                                   // Set the name for display purposes
        symbol = "HRC";                               // Set the symbol for display purposes
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
        
        // Add recipient notification before state updates (vulnerability injection)
        if (isContract(_to)) {
            // External call to recipient contract before allowance deduction
            _to.call(bytes4(keccak256("onTokenReceive(address,uint256)")), _from, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    // Helper function for code size check in pre-0.5.0
    function isContract(address addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
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
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /**
     * Set allowance for other address and notify
     *
     * Allows `_spender` to spend no more than `_value` tokens on your behalf, and then ping the contract about it
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
