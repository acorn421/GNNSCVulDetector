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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the spender contract BEFORE updating the allowance state. The vulnerability works as follows:
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **Transaction 1**: Attacker calls approve() with their malicious contract as _spender. The external call to receiveApproval() is made BEFORE the allowance is updated, allowing the malicious contract to:
 *    - Call transferFrom() with the old allowance values
 *    - Potentially call approve() again recursively before the original allowance is set
 * 
 * 2. **Transaction 2+**: The attacker can leverage the inconsistent state created in Transaction 1 to:
 *    - Exploit race conditions between approval updates
 *    - Use accumulated allowance inconsistencies from previous transactions
 *    - Chain multiple approvals to build up exploitable state
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability requires the attacker to first deploy a malicious contract that implements receiveApproval()
 * - The malicious contract needs to accumulate state across multiple approve() calls
 * - Each transaction builds upon the state modifications from previous transactions
 * - The attacker can't exploit all the inconsistencies in a single atomic transaction due to gas limits and the need to interact with the accumulated state
 * 
 * **State Accumulation:**
 * - Each approve() call allows the attacker to manipulate allowance state before it's finalized
 * - Multiple transactions allow building up complex attack scenarios
 * - The attacker can create cascading effects where each approval creates more exploitable state
 * 
 * This creates a realistic vulnerability pattern seen in production where external calls before state updates enable multi-transaction reentrancy attacks.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Pre-approval notification to spender before state update
        if (isContract(_spender)) {
            tokenRecipient(_spender).receiveApproval(msg.sender, _value, this, "");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    // Helper function to check if address is contract (since .code is not available in 0.4.19)
    function isContract(address _addr) internal view returns (bool is_contract) {
        uint length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
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
