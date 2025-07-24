/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
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
 * **Vulnerability Injection Summary:**
 * 
 * **1. Specific Changes Made:**
 * - Added an external call to `tokenRecipient(_from).receiveApproval()` positioned AFTER the initial checks but BEFORE state updates
 * - The external call serves as a "burn notification" mechanism that appears legitimate but creates a reentrancy vulnerability
 * - Added a check `_from != msg.sender && _from.code.length > 0` to ensure the call only happens for contract addresses burning on behalf of others
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * 
 * **Setup Phase (Transaction 1):**
 * - Attacker deploys a malicious contract that implements `tokenRecipient` interface
 * - The malicious contract holds tokens and grants allowance to an attacker-controlled EOA
 * - The malicious contract's `receiveApproval` function is designed to call back into `burnFrom`
 * 
 * **Exploitation Phase (Transaction 2):**
 * - Attacker calls `burnFrom(maliciousContract, amount)` with their approved allowance
 * - The function passes initial checks (balance and allowance validation)
 * - The external call to `maliciousContract.receiveApproval()` is made BEFORE state updates
 * - Inside `receiveApproval`, the malicious contract calls `burnFrom` again
 * - Since state hasn't been updated yet, the same allowance can be used multiple times
 * - This allows burning more tokens than the allowance should permit
 * 
 * **3. Why Multi-Transaction is Required:**
 * 
 * **State Dependency:** The vulnerability relies on:
 * - Prior allowance setup (requires separate `approve` transaction)
 * - The attacker's malicious contract being deployed and funded with tokens
 * - The allowance must be established before the attack can begin
 * 
 * **Persistent State Exploitation:** 
 * - The vulnerability exploits the fact that `allowance[_from][msg.sender]` hasn't been decremented during the external call
 * - Each reentrant call sees the same original allowance value
 * - This allows recursive burning beyond what should be permitted
 * 
 * **Attack Sequence Requirements:**
 * 1. **Transaction 1:** Deploy malicious contract and set up allowances
 * 2. **Transaction 2:** Execute the reentrancy attack through `burnFrom`
 * 3. **Multiple internal calls:** During transaction 2, the external call enables multiple reentrant `burnFrom` calls
 * 
 * **Impact:** An attacker can burn significantly more tokens than their allowance permits, potentially draining the victim's balance completely while only having limited approved allowance. This breaks the fundamental security guarantee of the allowance mechanism in ERC-20 tokens.
 */
/**
 *Submitted for verification at Etherscan.io on 2019-11-13
*/

/**
 *Submitted for verification at Etherscan.io on 2019-06-27
*/

pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

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
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor() public {
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
        emit Transfer(_from, _to, _value);
        
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
        allowance[_from][msg.sender] = allowance[_from][msg.sender].sub(_value);
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
        emit Approval(msg.sender, _spender, _value);
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
        emit Burn(msg.sender, _value);
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify the token holder about the burn operation before updating state
        // This creates a reentrancy window where state hasn't been updated yet
        if (_from != msg.sender && isContract(_from)) {
            tokenRecipient(_from).receiveApproval(msg.sender, _value, this, "BURN_NOTIFICATION");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] = balanceOf[_from].sub(_value);                         // Subtract from the targeted balance
        allowance[_from][msg.sender] = allowance[_from][msg.sender].sub(_value);             // Subtract from the sender's allowance
        totalSupply = totalSupply.sub(_value);                              // Update totalSupply
        emit Burn(_from, _value);
        return true;
    }

    // Helper for contract detection for ^0.4.16
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}