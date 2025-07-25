/*
 * ===== SmartInject Injection Details =====
 * Function      : approveAndCall
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a redundant allowance update after the external call. This creates a critical timing window where:
 * 
 * 1. **Transaction 1**: User calls approveAndCall, setting allowance via approve(), then external call to malicious contract
 * 2. **Malicious contract**: Receives notification but doesn't immediately exploit - instead stores the approval information
 * 3. **Transaction 2**: Malicious contract calls transferFrom using the previously approved allowance
 * 4. **Transaction 3**: Original user calls approveAndCall again (thinking previous approval was used), but the redundant allowance update after external call creates a double-approval scenario
 * 
 * The vulnerability exploits the fact that allowance state persists between transactions, and the redundant state update after the external call creates opportunities for accumulated allowance manipulation across multiple transactions. An attacker can build up multiple approvals over time and exploit them in sequence.
 * 
 * The key insight is that the redundant allowance[msg.sender][_spender] = _value line after the external call creates a state inconsistency window that can be exploited across multiple transactions, as the external contract can manipulate the approval state before this final update occurs.
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
        emit Transfer(_from, _to, _value);
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
     */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // External call with state dependency - vulnerable to multi-transaction reentrancy
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            
            // Critical flaw: State updates after external call
            // This creates a window for accumulated allowance exploitation
            allowance[msg.sender][_spender] = _value;
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            return true;
        }
    }
}