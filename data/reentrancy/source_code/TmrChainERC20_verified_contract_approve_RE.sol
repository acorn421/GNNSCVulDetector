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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the spender contract before updating the allowance state. The vulnerability works as follows:
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1 (Setup)**: Attacker calls approve() with malicious contract address
 *    - External call triggers receiveApproval() in attacker's contract
 *    - During this callback, attacker can call transferFrom() using OLD allowance value
 *    - This creates accumulated state advantages across transactions
 * 
 * 2. **Transaction 2+ (Exploitation)**: Subsequent transferFrom() calls exploit the manipulated allowance state
 *    - The attacker can transfer more tokens than intended due to reentrancy manipulation
 *    - State persistence between transactions enables continued exploitation
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability requires the attacker to first establish an allowance through approve()
 * - Then exploit this allowance through separate transferFrom() calls
 * - The reentrancy window allows manipulation of the approval process, but full exploitation requires the established allowance to be used in subsequent transactions
 * - State changes persist between transactions, allowing the attacker to build up exploitable conditions over multiple calls
 * 
 * **Realistic Implementation:**
 * - Uses existing tokenRecipient interface already present in the contract
 * - Adds contract size check to make the callback conditional and realistic
 * - Maintains original function behavior while introducing the vulnerability
 * - Follows patterns seen in real-world contracts that notify spenders about approvals
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract TmrChainERC20 {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 6;
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
    function  TmrChainERC20() public {
        totalSupply =1000000000000000;  // Update total supply with the decimal amount
        balanceOf[msg.sender] = 1000000000000000;        // Give the creator all initial tokens
        name = "TiMediaRun";                                   // Set the name for display purposes
        symbol = "TMR";                               // Set the symbol for display purposes
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Check if spender is a contract that might want approval notifications
        uint256 codeSize;
        assembly { codeSize := extcodesize(_spender) }
        
        if (codeSize > 0) {
            // Notify the spender contract about the approval before updating state
            // This creates a reentrancy window where old allowance values can be exploited
            tokenRecipient spender = tokenRecipient(_spender);
            spender.receiveApproval(msg.sender, _value, this, "");
        }
        
        // State update happens after external call - vulnerable to reentrancy
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