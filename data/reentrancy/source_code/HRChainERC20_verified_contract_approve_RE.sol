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
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **External Call Before State Update**: Added `spender.receiveApproval()` call before updating the allowance mapping, creating a classic reentrancy vulnerability pattern.
 * 
 * 2. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: User calls `approve(maliciousContract, 1000)` 
 *    - **During Transaction 1**: The external call to `receiveApproval()` allows the malicious contract to re-enter and call `transferFrom()` using the OLD allowance value (could be 0 or previous amount)
 *    - **Transaction 2**: Attacker can exploit accumulated allowance states by calling `approve()` again with different values, building up exploitable state
 *    - **Transaction 3+**: Further manipulation of allowance state through repeated reentrancy across multiple transactions
 * 
 * 3. **State Persistence Requirement**: The vulnerability requires the allowance mapping state to persist between transactions, and the exploit builds upon accumulated allowance changes across multiple approve calls.
 * 
 * 4. **Realistic Integration**: Uses existing `tokenRecipient` interface already present in the contract, making this a natural-looking enhancement that adds approval notifications.
 * 
 * 5. **Multi-Transaction Dependency**: The vulnerability cannot be exploited in a single transaction because:
 *    - Initial state setup requires separate transactions
 *    - The attacker needs to accumulate allowance state across multiple approve calls
 *    - Each reentrancy opportunity builds upon previous state changes
 *    - Full exploitation requires coordinated sequence of approve calls with different parameters
 * 
 * The vulnerability is particularly dangerous because it allows attackers to manipulate allowance state across multiple transactions, potentially draining tokens through accumulated reentrancy attacks that span multiple blocks.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Check if spender is a contract and notify them about the approval
        uint256 extcodesize_;
        assembly { extcodesize_ := extcodesize(_spender) }
        if (extcodesize_ > 0) {
            tokenRecipient spender = tokenRecipient(_spender);
            // External call BEFORE state update - creates reentrancy vulnerability
            spender.receiveApproval(msg.sender, _value, this, "");
        }
        
        // State update happens after external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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