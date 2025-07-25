/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Violation of Checks-Effects-Interactions Pattern**: Moved the allowance update to occur AFTER the external call to the recipient contract, creating a critical window where state is inconsistent.
 * 
 * 2. **External Call Integration**: Added a realistic external call to `TokenRecipient(_to).onTokenTransfer()` which allows recipient contracts to execute arbitrary code during the transfer process.
 * 
 * 3. **Multi-Transaction Exploitation Path**: 
 *    - Transaction 1: Attacker calls transferFrom with a malicious contract as recipient
 *    - During the external call, the malicious contract can re-enter transferFrom while the allowance hasn't been updated yet
 *    - Transaction 2: The reentrant call finds the original allowance still intact and can transfer additional tokens
 *    - The vulnerability requires multiple function calls and persistent state manipulation across transactions
 * 
 * 4. **Stateful Nature**: The vulnerability depends on the allowance state remaining unchanged during the external call window, requiring multiple transactions to fully exploit the inconsistent state.
 * 
 * 5. **Realistic Implementation**: The token transfer notification pattern is commonly used in modern token contracts, making this vulnerability appear legitimate while being genuinely exploitable.
 * 
 * **Multi-Transaction Exploitation Requirements Met**:
 * - Requires at least 2 separate function calls (original + reentrant)
 * - Depends on persistent allowance state between transactions
 * - Cannot be exploited in a single atomic transaction without the external call opportunity
 * - State changes from the initial call enable the vulnerability in subsequent reentrant calls
 */
/**
 *Submitted for verification at Etherscan.io on 2019-11-13
*/

/**
 *Submitted for verification at Etherscan.io on 2019-06-27
*/

pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

library SafeMath {
    
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }
        uint256 c = a * b;
        assert(c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a / b;
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b <= a);
        return a - b;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }
}

// Moved TokenRecipient definition outside of LeeeMallToken, as a separate contract
contract TokenRecipient {
    function onTokenTransfer(address _from, uint256 _value, bytes _data) external returns (bool);
}

contract LeeeMallToken {
    using SafeMath for uint;
    string public name = "LeeeMall";
    string public symbol = "LEEE";
    uint8 public decimals = 18;
    uint256 public totalSupply = 1*1000*1000*1000*10*10**uint256(decimals);

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    event Burn(address indexed from, uint256 value);

    /**
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function LeeeMallToken(
    ) public {
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);

        require(balanceOf[_from] >= _value);
        
        require(balanceOf[_to].add(_value) > balanceOf[_to]);
        
        uint previousBalances = balanceOf[_from].add(balanceOf[_to]);
        
        balanceOf[_from] = balanceOf[_from].sub(_value);
        
        balanceOf[_to] = balanceOf[_to].add(_value);
        Transfer(_from, _to, _value);
        
        assert(balanceOf[_from].add(balanceOf[_to]) == previousBalances);
    }

    /**
     * Transfer tokens
     *
     * Send `_value` tokens to `_to` from your account
     *
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transfer(address _to, uint256 _value) public returns (bool success) {
        _transfer(msg.sender, _to, _value);
        return true;
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
        
        // Store original allowance for callback notification
        uint256 originalAllowance = allowance[_from][msg.sender];
        
        // Perform the transfer first (contains external call potential)
        _transfer(_from, _to, _value);
        
        // Notify recipient contract about the transfer (external call)
        if (isContract(_to)) {
            require(TokenRecipient(_to).onTokenTransfer(_from, _value, ""));
        }
        
        // Update allowance after external interactions
        allowance[_from][msg.sender] = allowance[_from][msg.sender].sub(_value);
        
        // Emit approval event for tracking
        Approval(_from, msg.sender, allowance[_from][msg.sender]);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Helper function to check if address is contract
    function isContract(address _addr) internal view returns (bool) {
        uint32 size;
        assembly {
            size := extcodesize(_addr)
        }
        return (size > 0);
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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
        Approval(msg.sender, _spender, _value);
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

    /**
     * Destroy tokens
     *
     * Remove `_value` tokens from the system irreversibly
     *
     * @param _value the amount of money to burn
     */
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        balanceOf[msg.sender] = balanceOf[msg.sender].sub(_value);            // Subtract from the sender
        totalSupply = totalSupply.sub(_value);                      // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    /**
     * Destroy tokens from other account
     *
     * Remove `_value` tokens from the system irreversibly on behalf of `_from`.
     *
     * @param _from the address of the senderT
     * @param _value the amount of money to burn
     */
    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                // Check if the targeted balance is enough
        require(_value <= allowance[_from][msg.sender]);    // Check allowance
        balanceOf[_from] = balanceOf[_from].sub(_value);                         // Subtract from the targeted balance
        allowance[_from][msg.sender] = allowance[_from][msg.sender].sub(_value);             // Subtract from the sender's allowance
        totalSupply = totalSupply.sub(_value);                              // Update totalSupply
        Burn(_from, _value);
        return true;
    }
}
