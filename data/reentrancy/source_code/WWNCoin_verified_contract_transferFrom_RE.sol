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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call Before State Updates**: Inserted a call to `ITokenReceiver(_to).onTokenReceived()` before the allowance is decremented. This violates the Checks-Effects-Interactions pattern and creates a reentrancy opportunity.
 * 
 * 2. **State Modification After External Call**: The critical state update `allowance[_from][msg.sender] -= _value` now happens AFTER the external call, making it vulnerable to reentrancy attacks.
 * 
 * 3. **Multi-Transaction Exploitation Scenario**:
 *    - **Transaction 1**: Attacker sets up allowance and calls transferFrom
 *    - **During External Call**: Recipient contract receives onTokenReceived callback
 *    - **Reentrant Call**: Malicious recipient contract calls transferFrom again with same allowance
 *    - **Transaction 2**: Subsequent legitimate transfers can be exploited due to manipulated allowance state
 *    - **State Accumulation**: Multiple rounds allow draining more tokens than originally approved
 * 
 * 4. **Why Multi-Transaction Required**:
 *    - The vulnerability requires persistent allowance state between calls
 *    - Initial allowance must be set in a previous transaction via approve()
 *    - The exploit works by making multiple transferFrom calls before allowance is properly decremented
 *    - Each reentrant call can transfer the full allowance amount again
 *    - The accumulated effect of multiple calls exceeds the original allowance
 * 
 * 5. **Realistic Implementation**: The addition of recipient notification is a common ERC-20 extension pattern, making this vulnerability subtle and realistic for production code.
 */
pragma solidity ^0.4.18;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

interface ITokenReceiver {
    function onTokenReceived(address _from, uint256 _value, address _operator) external;
}

contract WWNCoin {
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

    function WWNCoin (
    ) public {
        totalSupply = 250000000 * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = "WWN Coin";                                   // Set the name for display purposes
        symbol = "WWN";                               // Set the symbol for display purposes
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

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract about incoming transfer (vulnerable external call)
        if (isContract(_to)) {
            ITokenReceiver(_to).onTokenReceived(_from, _value, msg.sender);
        }
        
        // State update happens AFTER external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    // Helper to check if an address is a contract
    function isContract(address _addr) internal view returns (bool) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }
}
