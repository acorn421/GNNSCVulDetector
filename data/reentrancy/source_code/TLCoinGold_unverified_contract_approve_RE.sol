/*
 * ===== SmartInject Injection Details =====
 * Function      : approve
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the spender contract after setting the allowance. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `tokenRecipient(_spender).receiveApproval()` after setting allowance
 * 2. Added check for contract code to determine if spender is a contract
 * 3. Used try-catch to handle potential failures silently
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker deploys malicious contract and calls `approve()` with their contract as spender
 * 2. **Transaction 2**: During the external call in `receiveApproval()`, the malicious contract can:
 *    - Call `approve()` again to increase allowance further
 *    - Call `transferFrom()` to drain tokens using the approved allowance
 *    - Manipulate state between the allowance setting and external call completion
 * 3. **Transaction 3+**: Attacker can continue to exploit the manipulated allowance state
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability relies on the persistent state change in the `allowance` mapping
 * - The attacker needs to deploy a malicious contract first (separate transaction)
 * - The reentrancy callback allows manipulation of allowance values that persist beyond the initial transaction
 * - Subsequent `transferFrom()` calls can exploit the manipulated allowance state
 * - The stateful nature means the exploit builds upon previous transaction results
 * 
 * **Realistic Integration:**
 * - Adding approval notifications is a common pattern in DeFi protocols
 * - The external call appears as a legitimate feature for contract integration
 * - The try-catch pattern maintains backward compatibility with non-contract addresses
 */
pragma solidity ^0.4.19;

interface tokenRecipient {
    function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public;
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
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function ERC20(
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
        Transfer(_from, _to, _value);

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
        // Update allowance before external call
        allowance[msg.sender][_spender] = _value;
        
        // Notify spender contract if it has code (stateful external call)
        if (isContract(_spender)) {
            // External call that enables reentrancy - spender can call back
            tokenRecipient(_spender).receiveApproval(msg.sender, _value, this, "");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }

    // Helper function compatible with Solidity 0.4.x for contract detection
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
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
/*       TLCG TOKEN STARTS HERE       */
/******************************************/

contract TLCoinGold is ERC20 {


    /* Initializes contract with initial supply tokens to the creator of the contract */
    function TLCoinGold() ERC20(10000000, "TL Coin Gold", "TLCG") public {}


    function multisend(address[] dests, uint256[] values) public returns (uint256) {
        uint256 i = 0;
        while (i < dests.length) {
           transfer(dests[i], values[i]);
           i += 1;
        }
        return(i);
    }
    
}
