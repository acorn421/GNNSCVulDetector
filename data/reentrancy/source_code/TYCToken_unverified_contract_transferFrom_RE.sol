/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract (_to) before updating the allowance state. The vulnerability works as follows:
 * 
 * **Changes Made:**
 * 1. Added a conditional external call to the recipient contract using `_to.call()` with `onTokenReceived` signature
 * 2. The call is made BEFORE the allowance is decremented, creating a reentrancy window
 * 3. Added a check for contract code existence to make the call realistic
 * 4. The external call is made with transfer details, enabling the recipient to act on this information
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **Transaction 1**: Attacker deploys a malicious contract that implements `onTokenReceived`
 * 2. **Transaction 2**: Token holder approves the attacker's contract for a certain amount
 * 3. **Transaction 3**: Attacker calls `transferFrom` with their malicious contract as `_to`
 * 4. **During Transaction 3**: The malicious contract's `onTokenReceived` is called before allowance is decremented
 * 5. **Reentrancy Attack**: The malicious contract can now call `transferFrom` again with the same allowance value
 * 6. **State Accumulation**: Each reentrant call exploits the same allowance value across multiple nested calls
 * 
 * **Why Multi-Transaction is Required:**
 * - The allowance must be set in a previous transaction through `approve()`
 * - The attacker needs to deploy their malicious contract beforehand
 * - The exploitation requires the contract to be called as the recipient, which requires setup
 * - The state (allowance mapping) persists between transactions and can be exploited multiple times
 * - The vulnerability builds upon the persistent allowance state that was established in earlier transactions
 * 
 * **Realistic Nature:**
 * - Token notifications to recipient contracts are common in modern ERC-20 implementations
 * - The code appears to be a legitimate attempt to notify recipients about incoming transfers
 * - The vulnerability is subtle and could easily be missed in code reviews
 * - The pattern follows real-world token implementations that include recipient callbacks
 */
/**
 *Submitted for verification at Etherscan.io on 2019-11-06
*/

pragma solidity ^0.4.16;

contract owned {
    address public owner;
    function owned() public {
        owner = msg.sender;
    }
    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
}

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

/// ERC20 standard，Define the minimum unit of money to 18 decimal places,
/// transfer out, destroy coins, others use your account spending pocket money.
contract TokenERC20 {
    uint256 public totalSupply;
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    /**
     * Internal transfer, only can be called by this contract.
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
     * Send `_value` tokens to `_to` from your account.
     *
     * @param _to The address of the recipient.
     * @param _value the amount to send.
     */
    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    /**
     * Transfer tokens from other address.
     *
     * Send `_value` tokens to `_to` in behalf of `_from`.
     *
     * @param _from The address of the sender.
     * @param _to The address of the recipient.
     * @param _value the amount to send.
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to recipient before state update - enables reentrancy
        uint length;
        assembly {
            length := extcodesize(_to)
        }
        if (length > 0) {
            // call was originally using abi.encodeWithSignature, which is fine for Solidity >= 0.4.0
            // this pattern is compatible if call is used correctly
            bool callSuccess;
            bytes memory data = abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value);
            assembly {
                callSuccess := call(gas, _to, 0, add(data, 32), mload(data), 0, 0)
            }
            require(callSuccess);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }
    /**
     * Set allowance for other address.
     *
     * Allows `_spender` to spend no more than `_value` tokens in your behalf.
     *
     * @param _spender The address authorized to spend.
     * @param _value the max amount they can spend.
     */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        require((_value == 0) || (allowance[msg.sender][_spender] == 0));
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /**
     * Set allowance for other address and notify.
     *
     * Allows `_spender` to spend no more than `_value` tokens in your behalf, and then ping the contract about it.
     *
     * @param _spender The address authorized to spend.
     * @param _value the max amount they can spend.
     * @param _extraData some extra information to send to the approved contract.
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

     /**
     * Destroy tokens
     *
     * Remove `_value` tokens from the system irreversibly.
     *
     * @param _value the amount of money to burn.
     */
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        Burn(msg.sender, _value);
        return true;
    }

    /**
     * Destroy tokens from other account.
     *
     * Remove `_value` tokens from the system irreversibly on behalf of `_from`.
     *
     * @param _from the address of the sender.
     * @param _value the amount of money to burn.
     */
    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        Burn(_from, _value);
        return true;
    }
}

/****************************/
/*       TYC TOKEN        */
/**************************/

/// TYC Protocol Token.
contract TYCToken is owned, TokenERC20 {

    string public constant name = "TYC Token";
    string public constant symbol = "TYC";
    uint8 public constant decimals = 18;
    uint256 public totalSupply = 190000000 * 10 ** uint256(decimals);

    /* Initializes contract with initial supply tokens to the creator of the contract. */
    function TYCToken() public {
        balanceOf[msg.sender] = totalSupply;
    }
}
