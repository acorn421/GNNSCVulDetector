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
 * Modified the transferFrom function to introduce a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before updating the allowance state. The vulnerability works as follows:
 * 
 * **Specific Changes Made:**
 * 1. Added a check for contract code at the recipient address using `_to.code.length > 0`
 * 2. Added an external call to `recipient.receiveApproval()` before the allowance state update
 * 3. The external call occurs after the allowance check but before the allowance reduction
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Setup Transaction:** Attacker gets approval for a large amount of tokens from victim
 * 2. **First Attack Transaction:** Attacker calls transferFrom() with a malicious contract as recipient
 * 3. **Reentrancy Chain:** The malicious contract's receiveApproval() function is called while allowance is still unchanged
 * 4. **Recursive Calls:** During the callback, the malicious contract calls transferFrom() again (multiple times) before the first call completes
 * 5. **State Exploitation:** Each recursive call sees the original allowance value since the allowance subtraction hasn't occurred yet
 * 
 * **Why Multiple Transactions Are Required:**
 * - The initial approval must be set in a separate transaction (approve() call)
 * - The attack requires the attacker to craft a malicious contract that implements the callback
 * - The exploit depends on the allowance state persisting between the external call and the state update
 * - Multiple recursive calls within the reentrancy chain drain more tokens than the original allowance should permit
 * 
 * **State Persistence Aspect:**
 * - The allowance mapping state persists between transactions
 * - The vulnerability exploits the window between external call and state update
 * - Each recursive call sees the same allowance value, allowing over-withdrawal
 * - The attack accumulates across multiple reentrant calls within the same transaction tree
 * 
 * This creates a classic reentrancy vulnerability where the external call allows the recipient contract to call back into transferFrom() before the allowance state is properly updated, enabling withdrawal of more tokens than approved.
 */
pragma solidity ^0.4.19;

interface tokenRecipient {
    function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; 
}

contract ERC20 {
    
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                    // Give the creator all initial tokens
        name = tokenName;                                       // Set the name for display purposes
        symbol = tokenSymbol;                                   // Set the symbol for display purposes
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);

        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(_from, _to, _value);

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
        
        // Notify recipient before state updates (introduces reentrancy vulnerability)
        uint length;
        assembly {
            length := extcodesize(_to)
        }
        if (length > 0) {
            tokenRecipient recipient = tokenRecipient(_to);
            recipient.receiveApproval(_from, _value, this, "");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
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

}

/******************************************/
/*       FMC TOKEN STARTS HERE       */
/******************************************/

contract FreeManCoin is ERC20 {
    /* Initializes contract with initial supply tokens to the creator of the contract */
    constructor() ERC20(50000000, "FreeMan Coin", "FMC") public {}

    function multisend(address[] dests, uint256[] values) public returns (uint256) {
        uint256 i = 0;
        while (i < dests.length) {
           transfer(dests[i], values[i]);
           i += 1;
        }
        return(i);
    }
    
}